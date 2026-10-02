using System.IO;
using HexLens.App.Controls;
using HexLens.Core.Documents;

namespace HexLens.App.Diagnostics;

/// <summary>
/// 界面层自检：跑真实的"键入十六进制 → 字节改变 → 撤销/重做 → 删除 → 另存回读"链路并输出报告。
///
/// 为什么要它：自动化环境（无交互桌面）里无法注入键盘输入，SendKeys / keybd_event 都会被系统拦掉。
/// 与其口头声称"编辑功能正常"，不如让这条链路有一个可重复执行的入口。
///
/// 用法：HexLens.App.exe --smoke-test=报告路径.txt
/// 退出码 = 失败项数量。
/// </summary>
public static class SmokeTest
{
    /// <summary>执行自检，返回失败项数量。</summary>
    /// <summary>模拟一次文本输入（用来验证"在 ASCII 列敲字符直接改写字节"）。</summary>
    private static void RaiseText(Controls.HexEditorView view, string text)
    {
        var composition = new System.Windows.Input.TextComposition(
            System.Windows.Input.InputManager.Current, view, text);

        var args = new System.Windows.Input.TextCompositionEventArgs(
            System.Windows.Input.InputManager.Current.PrimaryKeyboardDevice, composition)
        {
            RoutedEvent = System.Windows.Input.TextCompositionManager.TextInputEvent,
        };

        view.RaiseEvent(args);
    }

    /// <summary>模拟一次按键（用来验证"哪些键走半字节编辑"这类分派逻辑）。</summary>
    private static void RaiseKey(Controls.HexEditorView view, System.Windows.Input.Key key)
    {
        System.Windows.PresentationSource? source = System.Windows.PresentationSource.FromVisual(view);
        if (source is null) return;

        var args = new System.Windows.Input.KeyEventArgs(
            System.Windows.Input.Keyboard.PrimaryDevice, source, 0, key)
        {
            RoutedEvent = System.Windows.Input.Keyboard.KeyDownEvent,
        };

        view.RaiseEvent(args);
    }

    public static int Run(HexEditorView view, ViewModels.MainViewModel viewModel, string reportPath)
    {
        var lines = new List<string>();
        int passed = 0;
        int failed = 0;

        void Check(string name, bool ok, string detail = "")
        {
            if (ok)
            {
                passed++;
                lines.Add($"PASS  {name}");
            }
            else
            {
                failed++;
                lines.Add($"FAIL  {name}    {detail}");
            }
        }

        lines.Add($"HexLens 界面自检  {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        lines.Add(new string('-', 64));

        ByteDocument document = ByteDocument.FromBytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        view.Document = document;

        // ① 半字节编辑：先高位、后低位、然后光标前移
        view.RevealRange(0, 1);
        view.ApplyHexDigit(0xA);
        Check("输入高位 A：0x89 → 0xA9", document[0] == 0xA9, $"实际 0x{document[0]:X2}");
        Check("输入高位后光标不前进", view.CaretOffset == 0, $"实际 {view.CaretOffset}");

        view.ApplyHexDigit(0xB);
        Check("输入低位 B：0xA9 → 0xAB", document[0] == 0xAB, $"实际 0x{document[0]:X2}");
        Check("输入低位后光标前移", view.CaretOffset == 1, $"实际 {view.CaretOffset}");

        // ② 撤销 / 重做
        Check("此刻可撤销", document.CanUndo, "历史为空");
        document.Undo();
        Check("撤销一步回到 0xA9", document[0] == 0xA9, $"实际 0x{document[0]:X2}");
        document.Undo();
        Check("再撤销回到 0x89", document[0] == 0x89, $"实际 0x{document[0]:X2}");
        Check("历史已耗尽", !document.CanUndo, "仍可撤销");
        document.Redo();
        document.Redo();
        Check("重做两步回到 0xAB", document[0] == 0xAB, $"实际 0x{document[0]:X2}");

        // ③ 删除选区（删掉偏移 2 起的 0x4E 0x47，原偏移 4/5 的 0x0D 0x0A 应前移到 2/3）
        view.RevealRange(2, 2);
        view.DeleteSelection();
        Check("删除 2 字节后长度为 6", document.Length == 6, $"实际 {document.Length}");
        Check("删除后后续字节前移", document[2] == 0x0D && document[3] == 0x0A,
            $"实际 {document[2]:X2} {document[3]:X2}");

        // ④ 整字节写入
        view.RevealRange(0, 1);
        view.WriteByte(0x42);
        Check("WriteByte 覆盖首字节为 0x42", document[0] == 0x42, $"实际 0x{document[0]:X2}");

        // ⑤ 另存并回读
        // 临时文件放**报告同目录**，不用 %TEMP%：受限环境里用户临时目录可能不可写
        // （实测被 Access denied 拒过一次，导致自检无端失败）。
        string reportDirectory = Path.GetDirectoryName(Path.GetFullPath(reportPath)) ?? ".";
        string outputPath = Path.Combine(reportDirectory, $"smoke_roundtrip_{Guid.NewGuid():N}.bin");
        try
        {
            document.Save(outputPath);
            byte[] written = File.ReadAllBytes(outputPath);
            Check("另存落盘长度一致", written.Length == document.Length, $"文件 {written.Length} vs 文档 {document.Length}");
            Check("落盘内容与内存一致", written.AsSpan().SequenceEqual(document.Span), "内容不同");

            ByteDocument reloaded = ByteDocument.FromFile(outputPath);
            Check("回读内容一致", reloaded.Span.SequenceEqual(document.Span), "回读不同");
        }
        catch (Exception ex)
        {
            Check("另存与回读", false, ex.Message);
        }
        finally
        {
            if (File.Exists(outputPath)) File.Delete(outputPath);

            // ⚠️ FromFile 会在同目录留下隐藏工作副本，不清理就会越积越多
            //（上一次自检就在 artifacts/ 里留了 11 个 .smoke_roundtrip_*.bin.hexlens-work）。
            // 隐藏文件删除前要先去掉 Hidden 属性，否则会被拒 —— 这个坑本项目踩过四次了。
            string workCopy = Path.Combine(reportDirectory, $".{Path.GetFileName(outputPath)}.hexlens-work");

            if (File.Exists(workCopy))
            {
                File.SetAttributes(workCopy, FileAttributes.Normal);
                File.Delete(workCopy);
            }
        }

        // ⑥ 定位与滚动信息
        view.RevealRange(3, 1);
        Check("RevealRange 正确定位光标", view.CaretOffset == 3, $"实际 {view.CaretOffset}");
        Check("视图已完成布局", view.ActualWidth > 0 && view.ActualHeight > 0,
            $"尺寸 {view.ActualWidth:F0}×{view.ActualHeight:F0}");

        // ⑦ 选中即识别：选区一变就该自动给出编码结论（不需要切页或点按钮）
        try
        {
            int probe = Math.Min(16, viewModel.Document?.Length ?? 0);
            viewModel.ReportSelection(0, probe);
            Check("选中即识别：给出结论", !string.IsNullOrWhiteSpace(viewModel.SelectionCodecSummary),
                viewModel.SelectionCodecSummary);

            viewModel.ReportSelection(0, 0);
            Check("取消选中后回到提示态", !viewModel.HasSelectionCodec, "结论未清空");
        }
        catch (Exception ex)
        {
            Check("选中即识别链路不抛异常", false, ex.Message);
        }

        // ⑧ 智能复制：ASCII 内容应复制成文本，二进制内容才复制成十六进制
        //    （用户反馈过"选中文本复制出来却是一串 hex"，这里把它钉住）
        try
        {
            ByteDocument asciiClip = ByteDocument.FromBytes("flag{clipboard_test}"u8.ToArray());
            view.Document = asciiClip;
            view.RevealRange(0, asciiClip.Length);

            // 剪贴板是全局资源，可能被别的进程短暂占用 → 清空后重试几次。
            // 否则会把环境竞争误报成功能缺陷（这一项就假失败过一次）。
            const string expected = "flag{clipboard_test}";
            string copied = string.Empty;
            bool copiedOk = false;

            for (int attempt = 0; attempt < 3 && !copiedOk; attempt++)
            {
                try { System.Windows.Clipboard.Clear(); } catch { /* 占用时忽略，下一轮再试 */ }
                view.CopySelectionSmart();
                System.Threading.Thread.Sleep(60);

                try { copied = System.Windows.Clipboard.GetText(); } catch { copied = string.Empty; }
                copiedOk = copied == expected;
            }

            Check("智能复制：ASCII 选区复制为文本", copiedOk, $"实际复制到「{copied}」");
        }
        catch (Exception ex)
        {
            // 剪贴板在无交互会话里可能不可用 —— 记为跳过，不算失败
            lines.Add($"SKIP  智能复制（剪贴板不可用：{ex.Message}）");
        }

        // ⑨ 右键菜单确实构建出来了（构建失败时右键会"没反应"，且很难从代码看出）
        Check("十六进制视图：右键菜单已构建",
            view.ContextMenu is not null && view.ContextMenu.Items.Count >= 5,
            $"菜单项 {view.ContextMenu?.Items.Count ?? 0} 个");

        // ⑩ 右键菜单必须套用主题样式（默认 WPF 菜单是系统灰白方角，和纸感主界面割裂）
        System.Windows.Controls.ContextMenu? menu = view.ContextMenu;
        var paperBrush = view.TryFindResource("PaperBrush") as System.Windows.Media.SolidColorBrush;
        var menuBackground = menu?.Background as System.Windows.Media.SolidColorBrush;
        Check("右键菜单用主题纸色底（非系统默认灰）",
            menuBackground is not null && paperBrush is not null && menuBackground.Color == paperBrush.Color,
            $"菜单底色 {menuBackground?.Color}，主题纸色 {paperBrush?.Color}");

        if (menu is { Items.Count: > 0 } && menu.Items[0] is System.Windows.Controls.MenuItem firstItem)
        {
            var inkBrush = view.TryFindResource("InkSoftBrush") as System.Windows.Media.SolidColorBrush;
            var itemForeground = firstItem.Foreground as System.Windows.Media.SolidColorBrush;
            Check("右键菜单项用主题墨色字",
                itemForeground is not null && inkBrush is not null && itemForeground.Color == inkBrush.Color,
                $"菜单项字色 {itemForeground?.Color}，主题墨色 {inkBrush?.Color}");
        }

        // ⑪ 居中跳转：目标应落在可见区中间，而不是贴着顶边（线索点击的行为）
        try
        {
            var tall = ByteDocument.FromBytes(new byte[8192]);
            view.Document = tall;

            const int targetOffset = 4096;                  // 第 256 行
            int targetLine = targetOffset / HexEditorView.BytesPerLine;
            int expected = targetLine - view.VisibleLineCount / 2;

            view.RevealRangeCentered(targetOffset, 16);

            Check("居中跳转：目标落在可见区中间",
                Math.Abs(view.FirstVisibleLine - expected) <= 1,
                $"首行 {view.FirstVisibleLine}，期望 {expected}（目标第 {targetLine} 行）");
        }
        catch (Exception ex)
        {
            Check("居中跳转链路可用", false, ex.Message);
        }

        // ⑫ ASCII 列直接编辑：在 ASCII 列敲字符应改掉当前字节；在十六进制列则不该被字符输入误改
        try
        {
            ByteDocument asciiDoc = ByteDocument.FromBytes("ABC"u8.ToArray());
            view.Document = asciiDoc;
            view.RevealRange(0, 1);          // RevealRange 会把光标放回十六进制列

            // 反向：十六进制列收到字符输入，字节不应变化
            RaiseText(view, "Q");
            Check("十六进制列不会被字符输入改写", asciiDoc[0] == (byte)'A', $"实际 0x{asciiDoc[0]:X2}");

            // 正向：切到 ASCII 列后敲字符，应写入该字节并前进
            view.CaretOnAscii = true;
            view.RevealRange(0, 1);
            view.CaretOnAscii = true;
            RaiseText(view, "Z");
            Check("ASCII 列输入直接改写字节", asciiDoc[0] == (byte)'Z', $"实际 0x{asciiDoc[0]:X2}");
            Check("ASCII 列输入后光标前进", view.CaretOffset == 1, $"实际 {view.CaretOffset}");

            // 非 ASCII 一律拒绝：中文输入法的汉字、emoji、控制字符都不能污染文件
            view.CaretOnAscii = true;
            view.RevealRange(0, 1);
            view.CaretOnAscii = true;
            byte before = asciiDoc[0];

            RaiseText(view, "中");
            Check("非 ASCII 输入被拒绝（汉字）", asciiDoc[0] == before, $"实际 0x{asciiDoc[0]:X2}");

            RaiseText(view, "AB");
            Check("多字符输入被拒绝（粘贴/输入法上屏）", asciiDoc[0] == before, $"实际 0x{asciiDoc[0]:X2}");

            RaiseText(view, "\t");
            Check("控制字符输入被拒绝", asciiDoc[0] == before, $"实际 0x{asciiDoc[0]:X2}");

            // 插入语义：ASCII 列打字应该"塞进去"，后面的内容整体后移，而不是覆盖
            ByteDocument insDoc = ByteDocument.FromBytes("ABC"u8.ToArray());
            view.Document = insDoc;
            view.CaretOnAscii = true;
            view.RevealRange(0, 1);
            view.CaretOnAscii = true;
            RaiseText(view, "X");

            Check("ASCII 列输入是插入（长度 +1）", insDoc.Length == 4, $"实际 {insDoc.Length}");
            Check("插入后原内容整体后移",
                insDoc[0] == (byte)'X' && insDoc[1] == (byte)'A' && insDoc[2] == (byte)'B' && insDoc[3] == (byte)'C',
                $"实际 {insDoc[0]:X2} {insDoc[1]:X2} {insDoc[2]:X2} {insDoc[3]:X2}");

            // 删除：删掉光标处 1 字节后长度回落
            view.CaretOnAscii = true;
            view.RevealRange(0, 1);
            view.DeleteSelection();
            Check("删除后长度 -1", insDoc.Length == 3, $"实际 {insDoc.Length}");

            // 回归：0-9 / A-F 在 ASCII 列**不能**被半字节编辑吃掉
            // （用户反馈"个别按键会吃掉字符"，就是这 16 个键）
            ByteDocument nibbleDoc = ByteDocument.FromBytes("000"u8.ToArray());
            view.Document = nibbleDoc;
            view.CaretOnAscii = true;
            view.RevealRange(0, 1);
            view.CaretOnAscii = true;

            byte nibbleBefore = nibbleDoc[0];
            RaiseKey(view, System.Windows.Input.Key.D);      // 'D' 是合法十六进制数字
            Check("ASCII 列：hex 数字键不再被半字节编辑吃掉",
                nibbleDoc[0] == nibbleBefore, $"字节被改成了 0x{nibbleDoc[0]:X2}");

            // 对照：十六进制列仍然要走半字节编辑，否则就是把功能改坏了
            view.CaretOnAscii = false;
            view.RevealRange(0, 1);
            view.CaretOnAscii = false;
            RaiseKey(view, System.Windows.Input.Key.D);
            Check("十六进制列：hex 数字键仍走半字节编辑",
                nibbleDoc[0] != nibbleBefore, "字节没有被改，半字节编辑失效了");
        }
        catch (Exception ex)
        {
            Check("ASCII 列编辑链路可用", false, ex.Message);
        }

        // ⑬ 主题化弹窗：能构造出来、且主题令牌能解析。
        //    弹窗是"只能靠肉眼验"的典型盲区 —— 这里只构造、不 ShowDialog
        //    （ShowDialog 会阻塞，自检就卡住），但足以抓到最常见的问题：
        //    XAML 没被编译进去、资源键找不到、合并字典没接上。
        try
        {
            Type? dialogType = typeof(HexEditorView).Assembly
                .GetType("HexLens.App.Controls.ThemedDialog");

            Check("主题化弹窗类型已编译进程序集", dialogType is not null);

            if (dialogType is not null)
            {
                // 构造函数是 private（只允许经 ShowWarning/ShowInfo 使用）→ 走非公开构造
                object? instance = Activator.CreateInstance(dialogType, nonPublic: true);
                Check("主题化弹窗可实例化", instance is System.Windows.Window);

                if (instance is System.Windows.Window dialog)
                {
                    Check("弹窗内容已加载（XAML 解析成功）", dialog.Content is not null);
                    Check("弹窗能解析主题令牌：纸色底",
                        dialog.TryFindResource("PaperBrush") is System.Windows.Media.Brush);
                    Check("弹窗能解析主题令牌：墨色字",
                        dialog.TryFindResource("InkBrush") is System.Windows.Media.Brush);

                    dialog.Close();
                }
            }
        }
        catch (Exception ex)
        {
            Check("主题化弹窗链路可用", false, ex.Message);
        }

        lines.Add(new string('-', 64));
        lines.Add($"通过 {passed} 项，失败 {failed} 项");
        lines.Add($"视图尺寸 {view.ActualWidth:F0}×{view.ActualHeight:F0}，可见行数 {view.VisibleLineCount}，"
                  + $"字符宽 {view.CharacterWidth:F2}，行高 {view.LineHeight:F2}");

        string report = string.Join(Environment.NewLine, lines);
        try
        {
            File.WriteAllText(reportPath, report);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"报告写入失败：{ex.Message}");
        }

        Console.WriteLine(report);
        return failed;
    }
}
