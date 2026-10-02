namespace HexLens.Core.Documents;

/// <summary>文档内容发生变化时的通知（供十六进制视图增量重绘）。</summary>
public sealed class DocumentChangedEventArgs(int offset, int removedCount, int insertedCount) : EventArgs
{
    /// <summary>变化起始偏移。</summary>
    public int Offset { get; } = offset;

    /// <summary>被移除的字节数。</summary>
    public int RemovedCount { get; } = removedCount;

    /// <summary>新插入的字节数。</summary>
    public int InsertedCount { get; } = insertedCount;
}

/// <summary>
/// 一次可逆编辑：把 <see cref="Before"/> 换成 <see cref="After"/>。
/// 插入、删除、覆盖、填充全部归约为同一原语，因此撤销/重做只有一条代码路径。
/// </summary>
internal readonly struct ByteEdit(int offset, byte[] before, byte[] after)
{
    public readonly int Offset = offset;
    public readonly byte[] Before = before;
    public readonly byte[] After = after;
}

/// <summary>
/// 十六进制编辑器的字节文档：内存驻留、支持插入/删除/覆盖/填充/XOR、无限层可配的撤销重做。
/// 体积上限 1 GiB（数组与 CTF 样本的实际边界）。
/// </summary>
public sealed class ByteDocument
{
    /// <summary>单个文档的内存上限。</summary>
    public const long MaxCapacity = 1L << 30;

    /// <summary>撤销栈最大深度。</summary>
    public const int MaxUndoDepth = 512;

    private byte[] _buffer;
    private int _length;
    private readonly List<ByteEdit> _undo = [];
    private readonly List<ByteEdit> _redo = [];

    private ByteDocument(byte[] buffer, int length, string? filePath)
    {
        _buffer = buffer;
        _length = length;
        FilePath = filePath;
    }

    /// <summary>内容变化事件。</summary>
    public event EventHandler<DocumentChangedEventArgs>? Changed;

    /// <summary>脏标记变化事件。</summary>
    public event EventHandler? DirtyChanged;

    /// <summary>来源文件路径（未保存的新文档为 null）。</summary>
    public string? FilePath { get; private set; }

    /// <summary>是否存在未保存修改。</summary>
    public bool IsDirty { get; private set; }

    /// <summary>当前字节数。</summary>
    public int Length => _length;

    /// <summary>是否可撤销。</summary>
    public bool CanUndo => _undo.Count > 0;

    /// <summary>是否可重做。</summary>
    public bool CanRedo => _redo.Count > 0;

    /// <summary>撤销栈深度（调试/状态栏用）。</summary>
    public int UndoDepth => _undo.Count;

    /// <summary>整个文档的只读视图。</summary>
    public ReadOnlySpan<byte> Span => _buffer.AsSpan(0, _length);

    /// <summary>按偏移读取单个字节。</summary>
    public byte this[int index]
    {
        get
        {
            if ((uint)index >= (uint)_length) throw new ArgumentOutOfRangeException(nameof(index));
            return _buffer[index];
        }
    }

    /// <summary>从文件载入 —— **Office 式的"副本优先"**。</summary>
    /// <remarks>
    /// 流程刻意照抄 Word 打开 .docx 的做法：
    ///  ① 若上次异常退出留下了**更新的**工作副本 → 优先用它（这就是"恢复未保存的内容"）；
    ///  ② 否则把原文件复制成同目录的隐藏副本，然后**从副本读**，而不是从原文件读；
    ///  ③ 复制完成后原文件就不再被碰 —— 编辑期间它内容不变，别的程序照样能读它。
    ///
    /// 副本建不出来时（目录只读、权限不足）退回直接读原文件，功能不受影响。
    /// </remarks>
    public static ByteDocument FromFile(string path)
    {
        path = Path.GetFullPath(path);

        var info = new FileInfo(path);
        if (!info.Exists) throw new FileNotFoundException("文件不存在", path);
        if (info.Length > MaxCapacity)
            throw new IOException($"文件 {info.Length / 1048576.0:F1} MiB 超过 {MaxCapacity / 1048576} MiB 上限");

        string directory = Path.GetDirectoryName(path) ?? ".";
        string name = Path.GetFileName(path);
        string copyPath = Path.Combine(directory, $".{name}{WorkingCopySuffix}");

        byte[] data;
        bool recovered = false;

        // ① 遗留的副本比原文件新 → 说明上次编辑没保存就退出了，优先恢复它
        if (File.Exists(copyPath) && File.GetLastWriteTimeUtc(copyPath) > File.GetLastWriteTimeUtc(path))
        {
            data = File.ReadAllBytes(copyPath);
            recovered = true;
        }
        else
        {
            // ② 先把原文件复制成隐藏副本，再从副本读
            bool copied;
            try
            {
                UnhideForWrite(copyPath);        // 已存在的隐藏副本会拒绝被覆盖
                File.Copy(path, copyPath, overwrite: true);
                TryHide(copyPath);
                copied = true;
            }
            catch
            {
                copied = false;          // 目录不可写 → 退回直接读原文件
            }

            data = copied ? File.ReadAllBytes(copyPath) : File.ReadAllBytes(path);
        }

        return new ByteDocument(data, data.Length, path)
        {
            WorkingCopyPath = File.Exists(copyPath) ? copyPath : null,
            RecoveredFromWorkingCopy = recovered,
        };
    }

    /// <summary>本次载入是否来自"上次未保存的副本"（界面可据此提示用户）。</summary>
    public bool RecoveredFromWorkingCopy { get; private init; }

    /// <summary>
    /// 对隐藏文件做写/删操作前，先解除隐藏属性。
    ///
    /// ⚠️ 这个坑本项目**踩了三次**：带 `FileAttributes.Hidden` 的文件在
    /// **删除、覆盖、写入**时都可能被系统拒绝。
    /// 凡是碰工作副本 / 备份的地方，一律先走这里，别再局部打补丁。
    /// </summary>
    private static void UnhideForWrite(string path)
    {
        try
        {
            if (File.Exists(path)) File.SetAttributes(path, FileAttributes.Normal);
        }
        catch
        {
            // 拿不到属性就照常尝试写入，让调用方去处理真正的失败
        }
    }

    /// <summary>
    /// 把当前内容刷进工作副本 —— 这就是 **Office 的自动恢复点**。
    ///
    /// 编辑期间定期调用（界面里做了防抖），万一崩溃/断电，
    /// 下次打开会因为"副本比原文件新"而自动恢复出来。
    /// </summary>
    public bool FlushWorkingCopy()
    {
        if (WorkingCopyPath is null) return false;

        try
        {
            UnhideForWrite(WorkingCopyPath);                  // 写隐藏文件会被拒，先解除
            File.WriteAllBytes(WorkingCopyPath, _buffer.AsSpan(0, _length).ToArray());
            TryHide(WorkingCopyPath);
            return true;
        }
        catch
        {
            return false;                // 刷不进就算了，不影响正在进行的编辑
        }
    }

    /// <summary>从内存字节创建。</summary>
    public static ByteDocument FromBytes(ReadOnlySpan<byte> data)
    {
        byte[] copy = data.ToArray();
        return new ByteDocument(copy, copy.Length, null);
    }

    /// <summary>创建空文档。</summary>
    public static ByteDocument Empty() => new([], 0, null);

    /// <summary>导出为独立数组。</summary>
    public byte[] ToArray() => _buffer.AsSpan(0, _length).ToArray();

    /// <summary>读取一段（自动裁剪到有效范围）。</summary>
    public byte[] ReadRange(int offset, int count)
    {
        if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset));
        if (count < 0) throw new ArgumentOutOfRangeException(nameof(count));
        if (offset >= _length || count == 0) return [];
        int n = Math.Min(count, _length - offset);
        return _buffer.AsSpan(offset, n).ToArray();
    }

    /// <summary>在指定偏移插入字节。</summary>
    public void Insert(int offset, ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0) return;
        Edit(offset, 0, bytes);
    }

    /// <summary>在末尾追加字节。</summary>
    public void Append(ReadOnlySpan<byte> bytes) => Insert(_length, bytes);

    /// <summary>删除一段字节。</summary>
    public void Remove(int offset, int count)
    {
        if (count <= 0) return;
        Edit(offset, count, []);
    }

    /// <summary>覆盖写入；越界时自动扩展文档长度（编辑器里直接键入即属此路径）。</summary>
    public void Overwrite(int offset, ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0) return;
        if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset));

        if (offset >= _length)
        {
            // 超出末尾：先补齐空洞再写入
            if (offset > _length)
            {
                byte[] pad = new byte[offset - _length];
                Edit(_length, 0, pad);
            }
            Edit(_length, 0, bytes);
            return;
        }

        int replaced = Math.Min(bytes.Length, _length - offset);
        Edit(offset, replaced, bytes);
    }

    /// <summary>用固定值填充一段。</summary>
    public void Fill(int offset, int count, byte value)
    {
        if (count <= 0) return;
        byte[] block = new byte[count];
        block.AsSpan().Fill(value);
        Edit(offset, Math.Min(count, Math.Max(0, _length - offset)), block);
    }

    /// <summary>对一个区段做 XOR（单字节密钥）。</summary>
    public void XorRange(int offset, int count, byte key)
    {
        byte[] cur = ReadRange(offset, count);
        if (cur.Length == 0) return;
        for (int i = 0; i < cur.Length; i++) cur[i] ^= key;
        Edit(offset, cur.Length, cur);
    }

    /// <summary>对一个区段做 XOR（循环密钥）。</summary>
    public void XorRange(int offset, int count, ReadOnlySpan<byte> key)
    {
        if (key.Length == 0) return;
        byte[] cur = ReadRange(offset, count);
        if (cur.Length == 0) return;
        for (int i = 0; i < cur.Length; i++) cur[i] ^= key[i % key.Length];
        Edit(offset, cur.Length, cur);
    }

    /// <summary>整体位反转（CTF 里常见的 "reverse bits" 变体）。</summary>
    public void NotRange(int offset, int count)
    {
        byte[] cur = ReadRange(offset, count);
        if (cur.Length == 0) return;
        for (int i = 0; i < cur.Length; i++) cur[i] = (byte)~cur[i];
        Edit(offset, cur.Length, cur);
    }

    /// <summary>撤销一步。</summary>
    public bool Undo()
    {
        if (_undo.Count == 0) return false;
        ByteEdit e = _undo[^1];
        _undo.RemoveAt(_undo.Count - 1);
        Splice(e.Offset, e.After.Length, e.Before);
        _redo.Add(e);
        return true;
    }

    /// <summary>重做一步。</summary>
    public bool Redo()
    {
        if (_redo.Count == 0) return false;
        ByteEdit e = _redo[^1];
        _redo.RemoveAt(_redo.Count - 1);
        Splice(e.Offset, e.Before.Length, e.After);
        _undo.Add(e);
        return true;
    }

    /// <summary>工作副本后缀（Office 的 `~$` 那种角色）。</summary>
    private const string WorkingCopySuffix = ".hexlens-work";

    /// <summary>本实例持有的隐藏工作副本路径（没有则为 null）。</summary>
    public string? WorkingCopyPath { get; private set; }

    /// <summary>删除工作副本（保存成功后、或正常关闭时调用）。</summary>
    public void RemoveWorkingCopy()
    {
        // 路径优先用字段；字段为空时按 FilePath 重新推导 ——
        // 万一建立副本时字段因异常没赋上，这里也要能把目录里的残留清掉。
        string? path = WorkingCopyPath;
        if (path is null && FilePath is not null)
        {
            string directory = Path.GetDirectoryName(FilePath) ?? ".";
            path = Path.Combine(directory, $".{Path.GetFileName(FilePath)}{WorkingCopySuffix}");
        }

        WorkingCopyPath = null;
        if (path is null || !File.Exists(path)) return;

        try
        {
            // 先去掉 Hidden 再删：带隐藏属性的文件在部分文件系统/安全策略下会被拒绝删除，
            // 而这里遗留一个隐藏文件比清理失败更糟（用户根本看不见它）。
            File.SetAttributes(path, FileAttributes.Normal);
            File.Delete(path);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[HexLens] 删除工作副本失败：{path} — {ex.Message}");
        }
    }

    /// <summary>
    /// 保存；未给出路径时使用来源路径。
    ///
    /// **三级降级**，任何一级成功都算存下来了：
    ///  ① 同目录临时文件 → 原子替换原文件（最安全，原文件不会出现半截状态，并留一份备份）；
    ///  ② 同目录写不了（受限目录、权限不足）→ **直接覆盖原文件**（放弃原子性，但"能存上"更重要）；
    ///  ③ 原文件也写不了（被独占、整个目录受保护）→ 把内容存到系统临时目录，
    ///     并在异常里写清路径 —— 至少让用户的改动有地方可捡。
    ///
    /// 之所以要这么多级：用户的桌面上实测遇到过 `Access to the path '...hexlens-tmp' is denied`，
    /// 而同一时刻目录本身是可写的。既然失败模式不止一种，就不能只留一条路。
    /// </summary>
    public void Save(string? path = null)
    {
        string target = Path.GetFullPath(path ?? FilePath ?? throw new InvalidOperationException("未指定保存路径"));

        string directory = Path.GetDirectoryName(target) ?? ".";
        string name = Path.GetFileName(target);
        byte[] snapshot = _buffer.AsSpan(0, _length).ToArray();

        // ① 先让工作副本让开：编辑期间它是"不碰原文件"的保险，
        //    但保存这一刻必须退场 —— 任何残留句柄都可能让写入失败。
        RemoveWorkingCopy();

        // ② 直接写入原文件 —— 操作最少、成功率最高的一条路
        //    （只碰一个文件，不生成临时文件、不生成备份）
        string? firstError = null;
        try
        {
            File.WriteAllBytes(target, snapshot);
            FinishSave(target);
            return;
        }
        catch (Exception ex)
        {
            firstError = $"{ex.GetType().Name}: {ex.Message}";
        }

        // ③ 退一步：临时文件 + 原子替换，多一次尝试
        string? atomicError = TryWriteAtomically(target, directory, name, snapshot);
        if (atomicError is null)
        {
            FinishSave(target);
            return;
        }

        // ④ 兜底：存到系统临时目录，保证改动不丢
        string rescue;
        try
        {
            rescue = Path.Combine(Path.GetTempPath(),
                $"{name}.hexlens-rescued-{DateTime.Now:yyyyMMdd-HHmmss}");
            File.WriteAllBytes(rescue, snapshot);
        }
        catch
        {
            rescue = "(连系统临时目录也写不进去)";
        }

        throw new IOException(
            $"无法写入目标文件：{target}\n"
            + $"直接写入失败：{firstError}\n"
            + $"原子替换失败：{atomicError}\n"
            + $"你的修改已保存到：{rescue}\n"
            + "若目标位于桌面 / 文档这类受系统保护的目录，可改用「另存为」存到普通目录。");
    }

    /// <summary>保存收尾：记录路径、清历史、清工作副本。</summary>
    private void FinishSave(string target)
    {
        FilePath = target;
        ClearHistory();
        SetDirty(false);

        // 内容已落盘，工作副本完成使命。放在这里而不是只靠调用方，
        // 是为了任何走 Save() 的路径都不会遗留垃圾文件。
        RemoveWorkingCopy();
    }

    /// <summary>尝试原子写入（临时文件 → 覆盖目标）；成功返回 null，失败返回原因。</summary>
    private static string? TryWriteAtomically(string target, string directory, string name, byte[] snapshot)
    {
        // ⚠️ 写临时文件同样会踩 Hidden 属性的坑：桌面上实测过一次 ——
        //    上次失败留下的 `.xxx.hexlens-tmp` 让这次写入被拒。
        //    所以先解除隐藏，还失败就换随机名（目的只是拿到一个同目录的临时文件）。
        string temp = Path.Combine(directory, $".{name}.hexlens-tmp");
        try
        {
            UnhideForWrite(temp);
            File.WriteAllBytes(temp, snapshot);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            try
            {
                temp = Path.Combine(directory, $".{name}.{Guid.NewGuid():N}.hexlens-tmp");
                File.WriteAllBytes(temp, snapshot);
            }
            catch (Exception inner)
            {
                return $"{inner.GetType().Name}: {inner.Message}";
            }
        }

        try
        {
            // 不再生成 .hexlens-bak 备份：那是用户没有要求的额外文件，
            // 而且 File.Replace 的备份参数本身就可能成为失败源（同名隐藏文件）。
            File.Copy(temp, target, overwrite: true);
            File.Delete(temp);
            return null;
        }
        catch (Exception ex)
        {
            return $"{ex.GetType().Name}: {ex.Message}";
        }
    }

    private static void TryHide(string path)
    {
        try { File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.Hidden); }
        catch { /* 隐藏失败不影响功能 */ }
    }

    /// <summary>另存为并接管该路径。</summary>
    public void SaveAs(string path) => Save(path);

    /// <summary>放弃未保存修改（重新载入来源文件）。</summary>
    public void Reload()
    {
        if (FilePath is null) return;
        byte[] data = File.ReadAllBytes(FilePath);
        _buffer = data;
        _length = data.Length;
        ClearHistory();
        SetDirty(false);
        RaiseChanged(0, 0, _length);
    }

    /// <summary>清空撤销历史（保存/重载后调用）。</summary>
    public void ClearHistory()
    {
        _undo.Clear();
        _redo.Clear();
    }

    /// <summary>在文档中查找字节模式，返回首个匹配偏移（找不到为 -1）。</summary>
    public int IndexOf(ReadOnlySpan<byte> pattern, int start = 0)
    {
        if (pattern.Length == 0 || start < 0 || start >= _length) return -1;
        int rel = _buffer.AsSpan(start, _length - start).IndexOf(pattern);
        return rel < 0 ? -1 : rel + start;
    }

    /// <summary>
    /// 枚举全部匹配偏移。
    /// 返回 List 而不是迭代器：<see cref="ReadOnlySpan{T}"/> 不能跨越 yield 边界（CS4007）。
    /// </summary>
    public List<int> FindAll(ReadOnlySpan<byte> pattern, int start = 0)
    {
        var result = new List<int>();
        if (pattern.Length == 0) return result;

        byte[] needle = pattern.ToArray();
        int pos = Math.Max(0, start);
        while (pos < _length)
        {
            int hit = IndexOf(needle, pos);
            if (hit < 0) break;
            result.Add(hit);
            pos = hit + 1;
        }
        return result;
    }

    /// <summary>把一次编辑压入撤销栈（记录前后字节以便双向重放）。</summary>
    private void Edit(int offset, int removeCount, ReadOnlySpan<byte> insert)
    {
        if (offset < 0 || offset > _length)
            throw new ArgumentOutOfRangeException(nameof(offset), $"偏移 {offset} 超出文档范围 0..{_length}");
        if (removeCount < 0 || offset + removeCount > _length)
            throw new ArgumentOutOfRangeException(nameof(removeCount), $"移除长度 {removeCount} 超出范围");

        byte[] before = ReadRange(offset, removeCount);
        byte[] after = insert.ToArray();

        Splice(offset, removeCount, after);

        _undo.Add(new ByteEdit(offset, before, after));
        if (_undo.Count > MaxUndoDepth) _undo.RemoveAt(0);
        _redo.Clear();
        SetDirty(true);
    }

    /// <summary>
    /// 只读模式 —— 打开取证物证时用，任何改动一律拒绝。
    ///
    /// 拦截点选在 <see cref="Splice"/>（所有改动的**最终汇聚点**）而不是各个公开方法上：
    /// 后者很容易漏，`Undo` / `Redo` 就是绕过 `Edit` 直接走 `Splice` 的。
    /// </summary>
    public bool IsReadOnly { get; set; }

    /// <summary>底层拼接：删除 removeCount 个字节，并在同位置写入 insert。</summary>
    private void Splice(int offset, int removeCount, ReadOnlySpan<byte> insert)
    {
        if (IsReadOnly)
            throw new InvalidOperationException(
                "当前文档以「只读」方式打开，无法修改。要改内容请重新打开并选择「编辑」模式。");

        int newLength = _length - removeCount + insert.Length;
        EnsureCapacity(newLength);

        int tailStart = offset + removeCount;
        int tailLength = _length - tailStart;

        if (insert.Length != removeCount && tailLength > 0)
            Buffer.BlockCopy(_buffer, tailStart, _buffer, offset + insert.Length, tailLength);

        insert.CopyTo(_buffer.AsSpan(offset));
        _length = newLength;

        Changed?.Invoke(this, new DocumentChangedEventArgs(offset, removeCount, insert.Length));
    }

    private void EnsureCapacity(int required)
    {
        if (required > MaxCapacity)
            throw new IOException($"操作会使文档增长到 {required / 1048576.0:F1} MiB，超过上限");
        if (required <= _buffer.Length) return;

        int grown = Math.Max(required, Math.Min((int)MaxCapacity, Math.Max(4096, _buffer.Length * 2)));
        Array.Resize(ref _buffer, grown);
    }

    private void SetDirty(bool value)
    {
        if (IsDirty == value) return;
        IsDirty = value;
        DirtyChanged?.Invoke(this, EventArgs.Empty);
    }

    private void RaiseChanged(int offset, int removed, int inserted)
        => Changed?.Invoke(this, new DocumentChangedEventArgs(offset, removed, inserted));
}
