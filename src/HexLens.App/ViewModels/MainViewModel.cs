using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using HexLens.Core.Analysis;
using HexLens.Core.Carving;
using HexLens.Core.Clues;
using HexLens.Core.Documents;
using HexLens.Core.Formats;
using Microsoft.Win32;

namespace HexLens.App.ViewModels;

/// <summary>
/// 主视图模型：负责文档生命周期、后台分析调度、线索动作执行。
/// 分析全部在后台线程跑，结果回 UI 线程刷新集合。
/// </summary>
public sealed class MainViewModel : INotifyPropertyChanged
{
    private ByteDocument? _document;
    private AnalysisResult? _analysis;
    private bool _isAnalyzing;
    private string _statusMessage = "拖入文件，或点击「打开文件」开始";
    private string _codecStatus = "选中一段字节后点「分析选区」；未选中时默认分析文件开头 4 KiB";
    private string _decodePreviewText = string.Empty;
    private string _decodePreviewHex = string.Empty;
    private bool _hasDecodeResult;
    private byte[]? _codecSourceBytes;
    private string _codecSelectionText = string.Empty;
    private byte[]? _decodedBytes;
    private string _statusOffset = "0x00000000";
    private string _statusSelection = "无选区";
    private string _searchPattern = string.Empty;
    private string _searchStatus = "输入十六进制（4D 5A ?? ??）或文本后回车";
    private int _searchModeIndex;
    private long _analysisElapsedMs;

    public MainViewModel()
    {
        OpenFileCommand = new RelayCommand(_ => OpenFileDialogAndLoad());
        ReloadCommand = new RelayCommand(_ => ReloadDocument(), _ => _document is not null);
        AnalyzeCommand = new RelayCommand(async _ => await AnalyzeAsync(), _ => _document is not null);
        _autoRecover = new System.Windows.Threading.DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(2),
        };
        _autoRecover.Tick += (_, _) =>
        {
            _autoRecover.Stop();
            _document?.FlushWorkingCopy();      // 自动恢复点，学 Office
        };

        SaveCommand = new RelayCommand(_ => SaveDocument(), _ => _document is { IsDirty: true });
        SaveAsCommand = new RelayCommand(_ => SaveDocumentAs(), _ => _document is not null);
        UndoCommand = new RelayCommand(_ => { _document?.Undo(); RefreshAfterEdit(); }, _ => _document?.CanUndo == true);
        RedoCommand = new RelayCommand(_ => { _document?.Redo(); RefreshAfterEdit(); }, _ => _document?.CanRedo == true);
        ToggleThemeCommand = new RelayCommand(_ => Themes.ThemeManager.Toggle());
        SearchCommand = new RelayCommand(_ => RunSearch(), _ => _document is not null);
        GotoCommand = new RelayCommand(parameter => GotoFromText(parameter as string), _ => _document is not null);
    }

    /// <summary>属性变化通知。</summary>
    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>请求视图滚动并选中某个区间。</summary>
    public event Action<int, int>? RevealRequested;

    /// <summary>请求视图刷新整个十六进制区（编辑后）。</summary>
    public event Action? DocumentReplaced;

    /// <summary>请求视图重新读取文档（内容变化但对象未换）。</summary>
    public event Action? DocumentContentChanged;

    // ── 命令 ───────────────────────────────────────────────────────────────

    public RelayCommand OpenFileCommand { get; }

    public RelayCommand ReloadCommand { get; }

    public RelayCommand AnalyzeCommand { get; }

    public RelayCommand SaveCommand { get; }

    public RelayCommand SaveAsCommand { get; }

    public RelayCommand UndoCommand { get; }

    public RelayCommand RedoCommand { get; }

    public RelayCommand ToggleThemeCommand { get; }

    public RelayCommand SearchCommand { get; }

    public RelayCommand GotoCommand { get; }

    // ── 集合 ───────────────────────────────────────────────────────────────

    public ObservableCollection<ClueItem> Clues { get; } = [];

    public ObservableCollection<CarvedFileItem> Files { get; } = [];

    public ObservableCollection<StructureItem> StructureRoots { get; } = [];

    public ObservableCollection<LsbHitItem> LsbHits { get; } = [];

    public ObservableCollection<StringItem> Strings { get; } = [];

    public ObservableCollection<HistogramBar> Histogram { get; } = [];

    /// <summary>
    /// 直方图**纵坐标**刻度（自上而下 5 档：最大值 → 0）。
    /// 没有它就只能看出"哪根柱子高"，看不出"到底多少字节"。
    /// </summary>
    public ObservableCollection<string> HistogramAxis { get; } = [];

    public ObservableCollection<EntropyRegionItem> EntropyRegions { get; } = [];

    /// <summary>给十六进制视图画熵色带用的原始数据。</summary>
    public IReadOnlyList<EntropyBlock> EntropyBlocks { get; private set; } = [];

    /// <summary>搜索命中（十六进制视图会高亮它们）。</summary>
    public IReadOnlyList<SearchHit> SearchHits { get; private set; } = [];

    /// <summary>结构区域（带类别，供十六进制视图按类型着色）。</summary>
    public IReadOnlyList<StructureRegion> StructureRegions { get; private set; } = [];

    // ── 文档状态 ───────────────────────────────────────────────────────────

    public ByteDocument? Document
    {
        get => _document;
        private set
        {
            if (ReferenceEquals(_document, value)) return;
            _document = value;
            RaiseAllDocumentProps();
        }
    }

    public bool HasDocument => _document is not null;

    public string FileNameText => _document?.FilePath is null
        ? (HasDocument ? "未命名" : "未打开文件")
        : Path.GetFileName(_document.FilePath);

    public string FilePathText => _document?.FilePath ?? string.Empty;

    public string DirtyMark => _document?.IsDirty == true ? "●" : string.Empty;

    /// <summary>
    /// 窗口标题。特意带上**构建时间** —— 这样任何时候都能一眼确认"我跑的是哪一版"，
    /// 不用再靠猜、比时间戳或反查 DLL 符号。排查"改了怎么没生效"时这行字最值钱。
    /// </summary>
    public string TitleText => $"HexLens — {FileNameText}{BuildStamp}";

    /// <summary>构建时间（供界面直接绑定）。</summary>
    public string BuildStampText => BuildStamp;

    /// <summary>构建时间（直接读可执行文件的时间戳），形如 "  · 构建 09-28 19:42"。</summary>
    public static string BuildStamp { get; } = CreateBuildStamp();

    private static string CreateBuildStamp()
    {
        try
        {
            string? exe = Environment.ProcessPath;
            return exe is null ? string.Empty : $"  · 构建 {File.GetLastWriteTime(exe):MM-dd HH:mm}";
        }
        catch
        {
            return string.Empty;
        }
    }

    public bool IsAnalyzing
    {
        get => _isAnalyzing;
        private set
        {
            if (Set(ref _isAnalyzing, value)) Raise(nameof(AnalyzeButtonText));
        }
    }

    public string AnalyzeButtonText => _isAnalyzing ? "分析中…" : "重新分析";

    // ── 分析结论 ───────────────────────────────────────────────────────────

    public string TypeText => _analysis?.Identified?.Signature.Name ?? (HasDocument ? "未知类型" : "—");

    public string TypeDetailText => _analysis?.Identified is { } identified
        ? $"{identified.Signature.Description}"
        : (HasDocument ? "未匹配到已收录的文件签名（可能是纯文本、自定义格式或加密数据）" : string.Empty);

    public string SizeText => _analysis is null
        ? "—"
        : $"{_analysis.Length:N0} 字节（{FormatSize(_analysis.Length)}）";

    public string EntropyText => _analysis is null ? "—" : $"{_analysis.OverallEntropy:F3} bit/字节";

    public string CarrierText => _analysis?.CarrierDescription ?? "（当前类型不做像素/采样级分析）";

    public string Md5Text => _analysis?.Md5 ?? "—";

    public string Sha1Text => _analysis?.Sha1 ?? "—";

    public string Sha256Text => _analysis?.Sha256 ?? "—";

    public string Crc32Text => _analysis?.Crc32 ?? "—";

    public string ElapsedText => _analysis is null ? "—" : $"{_analysisElapsedMs} ms";

    public string GifFrameText => _analysis is { GifFrameCount: > 0 } a ? $"{a.GifFrameCount} 帧" : "—";

    public int ClueCount => Clues.Count;

    public int FileCount => Files.Count;

    public int LsbCount => LsbHits.Count;

    public int StringCount => Strings.Count;

    public bool HasClues => Clues.Count > 0;

    public bool HasLsbHits => LsbHits.Count > 0;

    public string DiagnosticText => _analysis is null || _analysis.Diagnostics.Count == 0
        ? string.Empty
        : string.Join("；", _analysis.Diagnostics.Distinct());

    // ── 状态栏 ─────────────────────────────────────────────────────────────

    public string StatusMessage
    {
        get => _statusMessage;
        set => Set(ref _statusMessage, value);
    }

    public string StatusOffset
    {
        get => _statusOffset;
        set => Set(ref _statusOffset, value);
    }

    public string StatusSelection
    {
        get => _statusSelection;
        set => Set(ref _statusSelection, value);
    }

    // ── 搜索 ───────────────────────────────────────────────────────────────

    public string SearchPattern
    {
        get => _searchPattern;
        set => Set(ref _searchPattern, value);
    }

    public string SearchStatus
    {
        get => _searchStatus;
        set => Set(ref _searchStatus, value);
    }

    /// <summary>0 = 十六进制，1 = 文本，2 = 正则。</summary>
    public int SearchModeIndex
    {
        get => _searchModeIndex;
        set => Set(ref _searchModeIndex, value);
    }

    // ── 打开 / 分析 ────────────────────────────────────────────────────────

    private void OpenFileDialogAndLoad()
    {
        var dialog = new OpenFileDialog
        {
            Title = "打开待分析的文件",
            Filter = "所有文件 (*.*)|*.*",
            CheckFileExists = true,
        };

        if (dialog.ShowDialog() == true) _ = OpenPathAsync(dialog.FileName);
    }

    /// <summary>
    /// 打开指定路径并自动分析。
    ///
    /// <paramref name="editMode"/> 为 <c>null</c> 时**弹窗询问**用户要只读还是编辑；
    /// 显式传 <c>true</c> / <c>false</c> 则直接采用、不询问 ——
    /// 命令行启动、自检、拖放批处理这些场景不能弹窗（一旦弹了就会卡住等人点）。
    /// </summary>
    public async Task OpenPathAsync(string path, bool? editMode = null)
    {
        try
        {
            // 取证（只看不动）和改字节（要写回）是两种心态，打开前问一句，
            // 比事后靠撤销去挽回靠谱得多。
            bool edit = editMode ?? HexLens.App.Controls.ThemedDialog.Ask(
                "以什么方式打开？",
                $"{Path.GetFileName(path)}\n\n"
                + "编辑：可以改字节，保存时写回原文件；可用撤销回退。\n"
                + "只读：任何修改都会被拒绝，保存也不会写盘 —— 看取证物证、只做分析时选它。",
                "编辑", "只读");

            StatusMessage = $"正在读取 {Path.GetFileName(path)} …";
            IsAnalyzing = true;

            ByteDocument document = await Task.Run(() => ByteDocument.FromFile(path));
            document.IsReadOnly = !edit;
            Document = document;
            DocumentReplaced?.Invoke();
            StatusMessage = edit ? $"已载入 {path}" : $"已载入 {path}（只读）";
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsDocumentReadOnly)));
            await AnalyzeAsync();
        }
        catch (Exception ex)
        {
            IsAnalyzing = false;
            StatusMessage = $"打开失败：{ex.Message}";
            HexLens.App.Controls.ThemedDialog.ShowWarning("打开文件失败", ex.Message);
        }
    }

    /// <summary>当前文档是否只读 —— 界面据此显示徽章、把编辑操作提示为不可用。</summary>
    public bool IsDocumentReadOnly => _document?.IsReadOnly == true;

    /// <summary>从内存字节创建文档（用于提取结果二次分析）。</summary>
    public async Task LoadBytesAsync(byte[] data, string displayName)
    {
        Document = ByteDocument.FromBytes(data);
        DocumentReplaced?.Invoke();
        StatusMessage = $"已载入提取结果 {displayName}（{data.Length:N0} 字节）";
        await AnalyzeAsync();
    }

    private void ReloadDocument()
    {
        if (_document?.FilePath is null) return;
        _ = OpenPathAsync(_document.FilePath);
    }

    /// <summary>执行完整分析（后台线程）。</summary>
    public async Task AnalyzeAsync()
    {
        if (_document is null) return;

        IsAnalyzing = true;
        StatusMessage = "分析中：签名扫描 / 隐写检测 / 结构解析…";

        ByteDocument document = _document;
        byte[] snapshot = document.ToArray();
        string? path = document.FilePath;

        try
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            AnalysisResult result = await Task.Run(() => FileAnalyzer.Analyze(snapshot, path));
            stopwatch.Stop();
            _analysisElapsedMs = stopwatch.ElapsedMilliseconds;

            // 文档在分析期间被改动则丢弃这次结果
            if (!ReferenceEquals(document, _document)) return;

            _analysis = result;
            ApplyAnalysis(result, snapshot);
            StatusMessage = result.ClueCount > 0
                ? $"分析完成：{result.ClueCount} 条线索，{result.Carve.Files.Count} 个已识别结构"
                : "分析完成：未发现明显藏匿特征";
        }
        catch (Exception ex)
        {
            StatusMessage = $"分析失败：{ex.Message}";
        }
        finally
        {
            IsAnalyzing = false;
        }
    }

    private void ApplyAnalysis(AnalysisResult result, byte[] snapshot)
    {
        Clues.Clear();
        foreach (Clue clue in result.Clues) Clues.Add(new ClueItem(clue));

        Files.Clear();
        foreach (Core.Carving.CarvedFile file in result.Carve.Files) Files.Add(new CarvedFileItem(file));

        // 按"文件"分组：以文件为根节点，其结构块作为子节点。
        // 否则同一个 EOCD 会因为既属于 ZIP 又被当成独立空归档而重复出现在树里。
        StructureRoots.Clear();
        foreach (CarvedFile file in result.Carve.Files)
        {
            if (file.Structure is null || file.Structure.Count == 0) continue;

            var root = new StructureNode(
                $"{file.Signature.Name} @ 0x{file.Offset:X}",
                file.Offset,
                file.Length,
                $"{file.SizeText} · {file.Note}",
                file.Structure);

            StructureRoots.Add(new StructureItem(root));
        }

        LsbHits.Clear();
        foreach (Core.Stego.LsbHit hit in result.LsbHits) LsbHits.Add(new LsbHitItem(hit));

        Strings.Clear();
        foreach (ExtractedString text in result.Strings) Strings.Add(new StringItem(text));

        EntropyRegions.Clear();
        foreach (EntropyBlock block in result.HighEntropyRegions) EntropyRegions.Add(new EntropyRegionItem(block));

        // 复用分析用的快照，避免再次整份拷贝
        EntropyBlocks = EntropyCalculator.Profile(snapshot, 256);

        // 结构区域：把结构树展平成带类别的区间
        // （PE 的 DOS头/PE头/节表/各节、PNG 的块、ZIP 的条目、RIFF 子块…）
        StructureRegions = StructureRegionBuilder.Build(result.Carve, snapshot.Length);

        long[] frequency = new long[256];
        foreach (byte b in snapshot) frequency[b]++;
        long max = Math.Max(1, frequency.Max());
        Histogram.Clear();
        for (int i = 0; i < 256; i++) Histogram.Add(new HistogramBar(i, frequency[i], frequency[i] / (double)max));

        // 纵坐标刻度：最大值 → 0，共 5 档（与 XAML 里那 5 条水平网格线一一对应）
        HistogramAxis.Clear();
        for (int step = 4; step >= 0; step--) HistogramAxis.Add(FormatCount(max * step / 4));

        DocumentContentChanged?.Invoke();
        RaiseAllAnalysisProps();
    }

    /// <summary>
    /// 把计数格式化成紧凑形式（12.3K / 1.2M）。
    /// 纵坐标标签太长会把图挤扁，所以上万就换单位。
    /// </summary>
    private static string FormatCount(long value) => value switch
    {
        >= 1_000_000 => $"{value / 1_000_000.0:0.#}M",
        >= 10_000 => $"{value / 1000.0:0.#}K",
        _ => value.ToString("N0"),
    };

    // ── 编辑与保存 ─────────────────────────────────────────────────────────

    /// <summary>编辑后刷新状态。</summary>
    public void RefreshAfterEdit()
    {
        Raise(nameof(DirtyMark));
        Raise(nameof(TitleText));
        UndoCommand.RaiseCanExecuteChanged();
        RedoCommand.RaiseCanExecuteChanged();
        SaveCommand.RaiseCanExecuteChanged();
        RestartAutoRecover();          // 重启自动恢复计时（学 Office 的 AutoRecover）
        DocumentContentChanged?.Invoke();
    }

    /// <summary>窗口关闭时清理隐藏工作副本，别给用户留垃圾文件。</summary>
    public void CleanupOnClose() => _document?.RemoveWorkingCopy();

    /// <summary>
    /// 自动恢复定时器（学 Office）：编辑停下 2 秒后把内容刷进隐藏副本。
    ///
    /// 为什么用防抖而不是每次按键都刷：大文件上每敲一个字节写一次盘是不可接受的；
    /// 停 2 秒再写既能把"崩溃丢多少"控制在很小范围，也不会拖慢输入。
    /// </summary>
    private readonly System.Windows.Threading.DispatcherTimer _autoRecover;

    private void RestartAutoRecover()
    {
        _autoRecover.Stop();
        if (_document is { IsDirty: true, WorkingCopyPath: not null }) _autoRecover.Start();
    }

    private void SaveDocument()
    {
        if (_document is null) return;
        try
        {
            _document.Save();
            _document.RemoveWorkingCopy();      // 保存成功 → 隐藏工作副本已完成使命
            StatusMessage = $"已保存到 {_document.FilePath}";
            RefreshAfterEdit();
        }
        catch (Exception ex)
        {
            // 只往状态栏写一行太容易被忽略 —— 用户会以为"点了没反应"。
            // 保存是最关键的动作，失败必须明确弹出来，并说清是哪个文件、什么原因。
            // 原因直接来自 ByteDocument.Save 抛出的异常（它会分别列出直接写入与原子替换的失败原因），
            // 这里不再自己"推测"原因 —— 猜错会把排查方向带偏。
            StatusMessage = $"保存失败：{ex.Message}";
            HexLens.App.Controls.ThemedDialog.ShowWarning(
                "保存失败",
                $"{ex.Message}\n\n目标文件：{_document.FilePath}\n\n"
                + "若提示文件被占用，通常是它正被其他程序打开（例如该程序正在运行）；"
                + "也可以改用「另存为」存到别处。");
        }
    }

    private void SaveDocumentAs()
    {
        if (_document is null) return;

        var dialog = new SaveFileDialog
        {
            Title = "另存为",
            FileName = _document.FilePath is null ? "output.bin" : Path.GetFileName(_document.FilePath),
            Filter = "所有文件 (*.*)|*.*",
        };

        if (dialog.ShowDialog() != true) return;

        try
        {
            _document.Save(dialog.FileName);
            _document.RemoveWorkingCopy();
            StatusMessage = $"已另存为 {dialog.FileName}";
            RaiseAllDocumentProps();
            RefreshAfterEdit();
        }
        catch (Exception ex)
        {
            StatusMessage = $"另存失败：{ex.Message}";
        }
    }

    // ── 提取 / 动作 ────────────────────────────────────────────────────────

    /// <summary>把文档中的一段导出为文件。</summary>
    public void ExtractRange(int offset, int length, string? suggestedName = null)
    {
        if (_document is null || length <= 0) return;
        if (offset < 0 || offset >= _document.Length) return;

        length = Math.Min(length, _document.Length - offset);
        byte[] payload = _document.ReadRange(offset, length);

        var dialog = new SaveFileDialog
        {
            Title = $"导出 0x{offset:X} 起的 {length:N0} 字节",
            FileName = suggestedName ?? $"extract_0x{offset:X}.bin",
            Filter = "所有文件 (*.*)|*.*",
        };

        if (dialog.ShowDialog() != true) return;

        try
        {
            File.WriteAllBytes(dialog.FileName, payload);
            StatusMessage = $"已导出 {length:N0} 字节 → {dialog.FileName}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"导出失败：{ex.Message}";
        }
    }

    /// <summary>把一段按 Base64 解码后导出。</summary>
    public void ExtractBase64(int offset, int length, string? suggestedName = null)
    {
        if (_document is null) return;

        try
        {
            string text = System.Text.Encoding.ASCII.GetString(_document.ReadRange(offset, length));
            byte[] decoded = Convert.FromBase64String(text);

            var dialog = new SaveFileDialog
            {
                Title = "Base64 解码结果",
                FileName = suggestedName ?? "decoded.bin",
                Filter = "所有文件 (*.*)|*.*",
            };
            if (dialog.ShowDialog() != true) return;

            File.WriteAllBytes(dialog.FileName, decoded);
            StatusMessage = $"Base64 解码 {decoded.Length:N0} 字节 → {dialog.FileName}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Base64 解码失败：{ex.Message}";
        }
    }

    /// <summary>执行线索上的动作。</summary>
    public void ExecuteClueAction(ClueAction action)
    {
        switch (action.Kind)
        {
            case ClueActionKind.ExtractRange:
                ExtractRange(action.Offset, action.Length, action.Hint);
                break;

            case ClueActionKind.RevealInHex:
                Reveal(action.Offset, action.Length);
                break;

            case ClueActionKind.DecodeBase64:
                ExtractBase64(action.Offset, action.Length, action.Hint);
                break;

            case ClueActionKind.SaveWholeBuffer:
                SaveDocumentAs();
                break;

            case ClueActionKind.ShowStructure:
                StatusMessage = "结构详情见「结构」页";
                break;

            case ClueActionKind.AnalyzeLsb:
                StatusMessage = "位平面分析见「隐写」页";
                break;

            case ClueActionKind.WritePayload:
                ApplyPayload(action);
                break;
        }
    }

    /// <summary>
    /// 把动作携带的字节写进文档（例如把文件头改成正确的签名）。
    ///
    /// 只读文档在这里明确拒绝并说明原因 —— 底层 ByteDocument 也会抛异常，
    /// 但那里抛出来的信息不如这里直白（它不知道用户点的是"修复"这个意图）。
    /// </summary>
    private void ApplyPayload(ClueAction action)
    {
        if (_document is null || action.Payload is not { Length: > 0 } payload) return;

        if (_document.IsReadOnly)
        {
            HexLens.App.Controls.ThemedDialog.ShowWarning(
                "文档是只读的",
                "当前文件以「只读」方式打开，不能写入。\n\n"
                + "要应用这个修复，请重新打开该文件并选择「编辑」模式。");
            return;
        }

        try
        {
            _document.Overwrite(action.Offset, payload);
            RefreshAfterEdit();
            StatusMessage = $"已写入 {payload.Length} 字节到 0x{action.Offset:X}（{Convert.ToHexString(payload)}）";
        }
        catch (Exception ex)
        {
            HexLens.App.Controls.ThemedDialog.ShowWarning("写入失败", ex.Message);
        }
    }

    /// <summary>在十六进制视图中定位区间。</summary>
    public void Reveal(int offset, int length)
    {
        if (_document is null) return;
        RevealRequested?.Invoke(Math.Max(0, offset), Math.Max(0, length));
        StatusSelection = length > 0 ? $"{offset:X8} 起 {length:N0} 字节" : "无选区";
    }

    /// <summary>从输入框跳转（支持 0x 前缀、十进制、十六进制）。</summary>
    private void GotoFromText(string? text)
    {
        if (string.IsNullOrWhiteSpace(text) || _document is null) return;

        text = text.Trim();
        bool parsed;
        long offset;

        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            parsed = long.TryParse(text[2..], System.Globalization.NumberStyles.HexNumber, null, out offset);
        else if (text.All(Uri.IsHexDigit) && text.Length > 4)
            parsed = long.TryParse(text, System.Globalization.NumberStyles.HexNumber, null, out offset);
        else
            parsed = long.TryParse(text, out offset);

        if (!parsed || offset < 0 || offset >= _document.Length)
        {
            StatusMessage = $"无法跳转到「{text}」";
            return;
        }

        Reveal((int)offset, 1);
    }

    // ── 搜索 ───────────────────────────────────────────────────────────────

    private void RunSearch()
    {
        if (_document is null || string.IsNullOrWhiteSpace(SearchPattern))
        {
            SearchHits = [];
            SearchStatus = "输入十六进制（4D 5A ?? ??）或文本后回车";
            DocumentContentChanged?.Invoke();
            return;
        }

        SearchMode mode = SearchModeIndex switch
        {
            1 => SearchMode.Text,
            2 => SearchMode.Regex,
            _ => SearchMode.HexPattern,
        };

        byte[] data = _document.ToArray();
        List<SearchHit> hits = SearchEngine.Search(data, new SearchQuery(SearchPattern, mode, IgnoreCase: mode != SearchMode.HexPattern));

        SearchHits = hits;
        SearchStatus = hits.Count == 0
            ? "没有匹配"
            : $"命中 {hits.Count:N0} 处" + (hits.Count > 0 ? $"，首个在 0x{hits[0].Offset:X}" : string.Empty);

        if (hits.Count > 0) Reveal(hits[0].Offset, hits[0].Length);
        DocumentContentChanged?.Invoke();
    }

    // ── 状态更新（供视图回调）─────────────────────────────────────────────

    /// <summary>十六进制视图报告光标位置。</summary>
    public void ReportCaret(int offset, long fileLength)
    {
        StatusOffset = $"0x{offset:X8}";
        _ = fileLength;
    }

    /// <summary>设置状态栏提示（供界面反馈"已复制"这类动作）。</summary>
    public void Notify(string message)
    {
        StatusMessage = message;
    }

    /// <summary>十六进制视图报告选区。</summary>
    public void ReportSelection(int start, int length)
    {
        bool changed = SelectionStart != start || SelectionLength != length;

        SelectionStart = start;
        SelectionLength = length;
        StatusSelection = length <= 0 ? "无选区" : $"0x{start:X} 起 {length:N0} 字节";
        Raise(nameof(SelectionInfoText));

        // 选区变了就重新识别一次（选中即识别）；只是光标移动则不必重算
        if (changed) AnalyzeSelectionInline();
    }

    // ── 编码识别（复用隔壁 Coding\ctfcodec 的编码库）────────────────────

    /// <summary>编码识别建议。</summary>
    public ObservableCollection<MagicItem> MagicSuggestions { get; } = [];

    /// <summary>XOR 暴力破解候选（按证据强度排序）。</summary>
    public ObservableCollection<XorCandidateItem> XorCandidates { get; } = [];

    /// <summary>是否已经有候选可展示（界面据此决定那一块显不显示）。</summary>
    public bool HasXorCandidates => XorCandidates.Count > 0;

    private string _xorStatusText = string.Empty;

    /// <summary>XOR 破解的状态说明（跑了什么范围、结果如何）。</summary>
    public string XorStatusText
    {
        get => _xorStatusText;
        private set
        {
            if (_xorStatusText == value) return;
            _xorStatusText = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(XorStatusText)));
        }
    }

    /// <summary>
    /// 对当前选区跑单字节 XOR 暴力破解。
    ///
    /// 范围取用户的选区：没选就取文件开头的一段（XOR 题的密文通常在文件前部，
    /// 而且整文件遍历既慢又没必要）。结果按"证据强度"排序 ——
    /// 撞上文件签名、含 flag 关键词的都排在纯"字符可读"前面。
    /// </summary>
    public void BruteForceXor()
    {
        XorCandidates.Clear();

        if (_document is null)
        {
            XorStatusText = "先打开一个文件。";
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(HasXorCandidates)));
            return;
        }

        int offset = 0;
        int length = Math.Min(_document.Length, 64 * 1024);

        if (SelectionLength > 0)
        {
            offset = SelectionStart;
            length = SelectionLength;
        }

        if (length <= 0)
        {
            XorStatusText = "选区为空。";
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(HasXorCandidates)));
            return;
        }

        ReadOnlySpan<byte> window = _document.Span.Slice(offset, Math.Min(length, _document.Length - offset));

        List<XorCandidate> found = XorBruteForcer.BruteForceSingleByte(window, top: 6);

        foreach (XorCandidate candidate in found)
        {
            XorCandidates.Add(new XorCandidateItem(candidate, offset, length));
        }

        XorStatusText = XorCandidates.Count == 0
            ? $"在 0x{offset:X} 起 {length} 字节上没找到像样的候选 —— 可能不是单字节 XOR，或者密钥更长。"
            : $"范围 0x{offset:X} 起 {length} 字节，试了 256 个单字节密钥，"
              + $"以下 {XorCandidates.Count} 个最像。点「用这个 key」应用到该区间。";

        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(HasXorCandidates)));
    }

    /// <summary>把某个 XOR 候选的密钥应用到它对应的区间。</summary>
    public void ApplyXorKey(XorCandidateItem item)
    {
        if (_document is null) return;

        if (_document.IsReadOnly)
        {
            HexLens.App.Controls.ThemedDialog.ShowWarning(
                "文档是只读的",
                "当前文件以「只读」方式打开，不能修改。\n\n"
                + "要应用这个密钥，请重新打开该文件并选择「编辑」模式。");
            return;
        }

        try
        {
            _document.XorRange(item.Offset, item.Length, item.Key);
            RefreshAfterEdit();
            StatusMessage = $"已用 key {item.KeyText} 对 0x{item.Offset:X} 起 {item.Length} 字节做 XOR";
        }
        catch (Exception ex)
        {
            HexLens.App.Controls.ThemedDialog.ShowWarning("应用失败", ex.Message);
        }
    }

    /// <summary>当前选区描述。</summary>
    public string SelectionInfoText => SelectionLength > 0
        ? $"选区：0x{SelectionStart:X} 起 {SelectionLength:N0} 字节"
        : "尚未选中内容（默认分析文件开头 4 KiB）";

    /// <summary>编码库状态。</summary>
    public string CodecLibraryText => Interop.CtfCodec.IsAvailable
        ? $"编码库 ctfcodec {Interop.CtfCodec.Version} · {Interop.CtfCodec.Algorithms().Count} 种算法"
        : $"编码库不可用：{Interop.CtfCodec.UnavailableReason}";

    /// <summary>编码面板状态提示。</summary>
    public string CodecStatus
    {
        get => _codecStatus;
        private set => Set(ref _codecStatus, value);
    }

    /// <summary>解码结果的可读文本。</summary>
    public string DecodePreviewText
    {
        get => _decodePreviewText;
        private set => Set(ref _decodePreviewText, value);
    }

    /// <summary>解码结果的十六进制预览。</summary>
    public string DecodePreviewHex
    {
        get => _decodePreviewHex;
        private set => Set(ref _decodePreviewHex, value);
    }

    /// <summary>是否已有解码结果。</summary>
    public bool HasDecodeResult
    {
        get => _hasDecodeResult;
        private set => Set(ref _hasDecodeResult, value);
    }

    /// <summary>选区起点。</summary>
    public int SelectionStart { get; private set; }

    /// <summary>选区长度。</summary>
    public int SelectionLength { get; private set; }

    /// <summary>对当前选区做编码识别（复用 ctfcodec 的启发式打分）。</summary>
    public void AnalyzeSelectionAsCodec()
    {
        MagicSuggestions.Clear();
        HasDecodeResult = false;
        DecodePreviewText = string.Empty;
        DecodePreviewHex = string.Empty;

        if (_document is null)
        {
            CodecStatus = "尚未打开文件";
            return;
        }

        if (!Interop.CtfCodec.IsAvailable)
        {
            CodecStatus = Interop.CtfCodec.UnavailableReason;
            return;
        }

        int start = SelectionLength > 0 ? SelectionStart : 0;
        int length = SelectionLength > 0
            ? Math.Min(SelectionLength, 65536)
            : Math.Min(_document.Length, 4096);

        byte[] raw = _document.ReadRange(start, length);
        if (raw.Length == 0)
        {
            CodecStatus = "选区为空";
            return;
        }

        // 底层识别接口接的是 NUL 结尾字符串：截到第一个 0 字节，再去掉首尾空白
        int nul = Array.IndexOf(raw, (byte)0);
        byte[] textBytes = nul >= 0 ? raw[..nul] : raw;
        string text = System.Text.Encoding.UTF8.GetString(textBytes).Trim();

        if (text.Length == 0)
        {
            CodecStatus = "选区内没有可识别文本（可能含大量 0 字节）";
            return;
        }

        _codecSourceBytes = System.Text.Encoding.UTF8.GetBytes(text);
        _codecSelectionText = text;
        List<Interop.MagicSuggestion> suggestions = Interop.CtfCodec.Suggest(text);

        foreach (Interop.MagicSuggestion suggestion in suggestions)
            MagicSuggestions.Add(new MagicItem(suggestion));

        CodecStatus = suggestions.Count == 0
            ? $"未匹配到已知编码（分析了 {_codecSourceBytes.Length:N0} 字节文本）"
            : $"匹配 {suggestions.Count} 种可能，点「用这个解码」查看还原结果";
    }

    /// <summary>数据检视结果（把选中字节按各种数值/文本类型解释）。</summary>
    public ObservableCollection<InspectorEntry> InspectorItems { get; } = [];

    /// <summary>数值解释是否按小端（默认是，x86 习惯）。</summary>
    public bool InspectorLittleEndian
    {
        get => _inspectorLittleEndian;
        set
        {
            if (Set(ref _inspectorLittleEndian, value)) RefreshInspector();
        }
    }

    /// <summary>
    /// 重算数据检视：把选区开头的字节按各种类型解释一遍。
    /// 至少喂 16 字节 —— 否则 uint64 / GUID 这类会因为"字节不够"显示不出来。
    /// </summary>
    public void RefreshInspector()
    {
        InspectorItems.Clear();
        if (_document is null || SelectionLength <= 0) return;

        int start = SelectionStart;
        if (start < 0 || start >= _document.Length) return;

        int length = Math.Min(Math.Max(SelectionLength, 16), Math.Min(_document.Length - start, 64));
        if (length <= 0) return;

        byte[] data = _document.ReadRange(start, length);
        foreach (DataInspector.Entry entry in DataInspector.Inspect(data, _inspectorLittleEndian))
        {
            InspectorItems.Add(new InspectorEntry(entry.Name, entry.Value));
        }
    }

    private bool _inspectorLittleEndian = true;

    /// <summary>选中片段的编码识别结论（一行摘要）。</summary>
    public string SelectionCodecSummary { get; private set; } = "选中一段字节，这里会立刻告诉你它可能是什么编码";

    /// <summary>选中片段按最优算法解出的内容预览。</summary>
    public string SelectionCodecPreview { get; private set; } = string.Empty;

    /// <summary>选中片段是否识别出了编码。</summary>
    public bool HasSelectionCodec { get; private set; }

    /// <summary>识别出的算法名（供「用这个解码」复用）。</summary>
    public string SelectionCodecAlgorithm { get; private set; } = string.Empty;

    /// <summary>
    /// 选中即识别：选区一变就尝试各种编码，并自动解码得分最高的那个。
    /// 与「编码」页的手动分析是同一套判定，差别只在于不需要用户切页或点按钮。
    /// </summary>
    public void AnalyzeSelectionInline()
    {
        // 数据检视跟着选区一起刷新（无论能不能识别出编码，字节本身的解释都该给出来）
        RefreshInspector();

        if (_document is null || SelectionLength <= 0)
        {
            ResetInlineCodec("选中一段字节，这里会立刻告诉你它可能是什么编码");
            return;
        }

        // 识别是启发式的，片段越小越准；也避免拖选大范围时反复计算造成卡顿
        if (SelectionLength > 8192)
        {
            ResetInlineCodec($"选中 {SelectionLength:N0} 字节 —— 太大了，编码识别只处理 8 KiB 以内的片段");
            return;
        }

        AnalyzeSelectionAsCodec();

        // 优先用 Core 的 Base64 探测：它支持 `key` / `data:` 这类前缀
        // （外部编码库的启发式对带前缀的整串给不出结论，snake.jpg 就是这样漏的）。
        Base64Probe.Result? probe = Base64Probe.Find(_codecSelectionText);
        if (probe is not null && probe.IsReadableText)
        {
            SelectionCodecAlgorithm = "base64";
            SelectionCodecSummary = probe.Skipped > 0
                ? $"base64 · 前缀「{_codecSelectionText[..probe.Skipped]}」之后才是载荷"
                : "base64";
            SelectionCodecPreview = Base64Probe.Preview(probe.Bytes);
            HasSelectionCodec = true;
            RaiseAllInlineProps();
            return;
        }

        if (MagicSuggestions.Count == 0)
        {
            ResetInlineCodec($"未匹配到已知编码（{SelectionLength:N0} 字节）");
            return;
        }

        MagicItem top = MagicSuggestions[0];
        SelectionCodecAlgorithm = top.Algorithm;
        SelectionCodecSummary = $"{top.Algorithm} {top.ScoreText} · {top.Reason}";

        byte[]? decoded = _codecSourceBytes is null
            ? null
            : Interop.CtfCodec.Decode(top.Algorithm, _codecSourceBytes);

        SelectionCodecPreview = decoded is null
            ? "（该算法无法解码这段内容）"
            : RenderAsText(decoded).Replace('\r', ' ').Replace('\n', ' ').Trim();

        HasSelectionCodec = true;
        RaiseAllInlineProps();
    }

    private void ResetInlineCodec(string summary)
    {
        HasSelectionCodec = false;
        SelectionCodecAlgorithm = string.Empty;
        SelectionCodecPreview = string.Empty;
        SelectionCodecSummary = summary;
        RaiseAllInlineProps();
    }

    private void RaiseAllInlineProps()
    {
        Raise(nameof(SelectionCodecSummary));
        Raise(nameof(SelectionCodecPreview));
        Raise(nameof(HasSelectionCodec));
        Raise(nameof(SelectionCodecAlgorithm));
    }

    /// <summary>用指定算法解码当前选区的文本。</summary>
    public void DecodeSelectionWith(string algorithm)
    {
        if (_document is null) return;
        if (_codecSourceBytes is null || _codecSourceBytes.Length == 0)
        {
            CodecStatus = "请先点「分析选区」";
            return;
        }

        byte[]? decoded = Interop.CtfCodec.Decode(algorithm, _codecSourceBytes);
        if (decoded is null)
        {
            CodecStatus = $"{algorithm} 解码失败：{Interop.CtfCodec.LastError}";
            return;
        }

        if (decoded.Length == 0)
        {
            CodecStatus = $"{algorithm} 解出 0 字节";
            return;
        }

        _decodedBytes = decoded;
        HasDecodeResult = true;
        DecodePreviewText = RenderAsText(decoded);
        DecodePreviewHex = RenderAsHex(decoded, 512);

        // 解码结果是不是一个文件？用与隐写/嵌入检测同一套结构化命中判据下结论
        StructuredHit? hit = StructuredHitDetector.Detect(decoded);
        CodecStatus = hit is not null
            ? $"{algorithm} → {decoded.Length:N0} 字节，识别为 {hit.Signature.Name} —— 可另存或作为新文档打开"
            : $"{algorithm} → {decoded.Length:N0} 字节（未识别出文件签名）";
    }

    /// <summary>把解码结果另存为文件。</summary>
    public void SaveDecodedResult()
    {
        if (_decodedBytes is null || _decodedBytes.Length == 0)
        {
            CodecStatus = "还没有解码结果";
            return;
        }

        var dialog = new SaveFileDialog
        {
            Title = "导出解码结果",
            FileName = "decoded.bin",
            Filter = "所有文件 (*.*)|*.*",
        };
        if (dialog.ShowDialog() != true) return;

        try
        {
            File.WriteAllBytes(dialog.FileName, _decodedBytes);
            CodecStatus = $"已导出 {_decodedBytes.Length:N0} 字节 → {dialog.FileName}";
        }
        catch (Exception ex)
        {
            CodecStatus = $"导出失败：{ex.Message}";
        }
    }

    /// <summary>把解码结果作为新文档打开并分析。</summary>
    public async Task OpenDecodedAsDocumentAsync()
    {
        if (_decodedBytes is null || _decodedBytes.Length == 0)
        {
            CodecStatus = "还没有解码结果";
            return;
        }

        await LoadBytesAsync(_decodedBytes, "（解码结果）");
    }

    private static string RenderAsText(byte[] data)
    {
        var builder = new System.Text.StringBuilder(data.Length);
        foreach (byte b in data)
        {
            builder.Append(b is >= 0x20 and < 0x7F || b is 0x0A or 0x0D or 0x09 ? (char)b : '.');
        }

        string text = builder.ToString();
        return text.Length > 4096 ? text[..4096] + "\n…（已截断显示，完整内容可另存）" : text;
    }

    private static string RenderAsHex(byte[] data, int limit)
    {
        int count = Math.Min(data.Length, limit);
        var builder = new System.Text.StringBuilder(count * 3 + 64);

        for (int i = 0; i < count; i++)
        {
            if (i > 0) builder.Append(i % 16 == 0 ? '\n' : ' ');
            builder.Append(data[i].ToString("X2"));
        }

        if (data.Length > count) builder.Append($"\n…（共 {data.Length:N0} 字节，仅显示前 {count:N0} 字节）");
        return builder.ToString();
    }

    // ── 属性通知 ───────────────────────────────────────────────────────────

    private bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        Raise(name);
        return true;
    }

    private void Raise(string? name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private void RaiseAllDocumentProps()
    {
        Raise(nameof(HasDocument));
        Raise(nameof(FileNameText));
        Raise(nameof(FilePathText));
        Raise(nameof(DirtyMark));
        Raise(nameof(TitleText));
        Raise(nameof(SizeText));
        Raise(nameof(TypeText));
        RaiseAllAnalysisProps();
        ReloadCommand.RaiseCanExecuteChanged();
        AnalyzeCommand.RaiseCanExecuteChanged();
        SaveCommand.RaiseCanExecuteChanged();
        SaveAsCommand.RaiseCanExecuteChanged();
        UndoCommand.RaiseCanExecuteChanged();
        RedoCommand.RaiseCanExecuteChanged();
        SearchCommand.RaiseCanExecuteChanged();
        GotoCommand.RaiseCanExecuteChanged();
    }

    private void RaiseAllAnalysisProps()
    {
        Raise(nameof(TypeText));
        Raise(nameof(TypeDetailText));
        Raise(nameof(SizeText));
        Raise(nameof(EntropyText));
        Raise(nameof(CarrierText));
        Raise(nameof(Md5Text));
        Raise(nameof(Sha1Text));
        Raise(nameof(Sha256Text));
        Raise(nameof(Crc32Text));
        Raise(nameof(ElapsedText));
        Raise(nameof(GifFrameText));
        Raise(nameof(ClueCount));
        Raise(nameof(FileCount));
        Raise(nameof(LsbCount));
        Raise(nameof(StringCount));
        Raise(nameof(HasClues));
        Raise(nameof(HasLsbHits));
        Raise(nameof(DiagnosticText));
    }

    private static string FormatSize(int bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:F1} KiB",
        _ => $"{bytes / 1048576.0:F2} MiB",
    };
}
