using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using HexLens.App.Controls;
using HexLens.App.Themes;
using HexLens.App.ViewModels;
using HexLens.Core.Analysis;
using HexLens.Core.Clues;
using HexLens.Core.Stego;

namespace HexLens.App;

/// <summary>主窗口：把视图模型的分析结论接到界面上。</summary>
public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel = new();
    private bool _startupSelectionApplied;
    private int _searchModeIndex;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _viewModel;

        // 高 DPI 屏幕上窗口的"逻辑尺寸"可能比工作区还大：这里按工作区收一下，
        // 保证首次打开不会被挤到屏幕外。（不设 MaxWidth/MaxHeight：用户在大屏上可以自由放大）
        Rect workArea = SystemParameters.WorkArea;
        Width = Math.Min(Width, Math.Max(MinWidth, workArea.Width - 24));
        Height = Math.Min(Height, Math.Max(MinHeight, workArea.Height - 24));

        _viewModel.DocumentReplaced += OnDocumentReplaced;
        _viewModel.DocumentContentChanged += OnDocumentContentChanged;
        _viewModel.RevealRequested += (offset, length) =>
        {
            SwitchToHexView();
            // 居中显示：线索/跳转的目标是"去看这段"，停在边缘会看不到上下文
            HexView.RevealRangeCentered(offset, length);
        };

        HexView.CaretMoved += (_, _) =>
        {
            _viewModel.ReportCaret(HexView.CaretOffset, HexView.Document?.Length ?? 0);
            _viewModel.ReportSelection(HexView.SelectionStart, HexView.SelectionLength);
        };
        HexView.ContentEdited += (_, _) => _viewModel.RefreshAfterEdit();
        HexView.ScrollInfoChanged += (_, _) => SyncScrollBar();

        Loaded += OnLoaded;
        SourceInitialized += (_, _) => ApplyWindowChromeTweaks();

        // 快捷键
        PreviewKeyDown += OnPreviewKeyDown;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        UpdateThemeIcon();
        UpdateSearchModeButton();
        ApplyStartupView();

        // 管理员运行时先把话说在前面：拖放会被 Windows 拦掉（UIPI），这看起来就像程序坏了
        if (IsRunningElevated())
        {
            _viewModel.Notify("以管理员身份运行：Windows 会禁止从资源管理器拖入文件，请改用「打开文件」按钮（普通权限运行即可拖放）");
        }

        // 截图核对菜单样式用：等布局完成后自动把右键菜单弹出来
        if (App.DemoContextMenu)
        {
            _ = Dispatcher.BeginInvoke(new Action(() =>
            {
                if (HexView.ContextMenu is not { } menu) return;
                HexView.Focus();
                menu.PlacementTarget = HexView;
                menu.Placement = System.Windows.Controls.Primitives.PlacementMode.Center;
                menu.IsOpen = true;
            }), System.Windows.Threading.DispatcherPriority.ApplicationIdle);
        }

        // 自检模式：等布局完成后跑真实编辑链路，然后按失败数退出
        if (App.SmokeTestReportPath is { } reportPath)
        {
            // _ = ：故意不等待（自检结束后由它自己 Shutdown）
            _ = Dispatcher.BeginInvoke(new Action(() =>
            {
                int failures = Diagnostics.SmokeTest.Run(HexView, _viewModel, reportPath);
                Application.Current.Shutdown(failures);
            }), System.Windows.Threading.DispatcherPriority.ApplicationIdle);
            return;
        }

        string? startup = App.StartupFile;
        if (!string.IsNullOrEmpty(startup) && File.Exists(startup))
            // 命令行带文件启动时不弹「只读/编辑」询问 —— 自动化场景会卡住等人点
            await _viewModel.OpenPathAsync(startup, editMode: true);
        else
            _viewModel.StatusMessage = "拖入文件，或点击「打开文件」开始分析";
    }

    /// <summary>应用 --view= 指定的初始视图。</summary>
    private void ApplyStartupView()
    {
        RadioButton? tab = App.StartupView switch
        {
            "structure" => TabStructure,
            "stego" => TabStego,
            "strings" => TabStrings,
            "codec" => TabCodec,
            "entropy" => TabEntropy,
            _ => null,
        };

        if (tab is not null) tab.IsChecked = true;
    }

    // ── 窗口外观 ───────────────────────────────────────────────────────────

    private void ApplyWindowChromeTweaks()
    {
        try
        {
            IntPtr handle = new WindowInteropHelper(this).Handle;

            // Win11：让系统为无边框窗口画圆角（比 AllowsTransparency 的软件渲染方案快得多）
            int preference = 2;   // DWMWCP_ROUND
            _ = DwmSetWindowAttribute(handle, 33, ref preference, sizeof(int));

            // 跟随系统深浅色画窗口边框/阴影
            int dark = ThemeManager.IsDark ? 1 : 0;
            _ = DwmSetWindowAttribute(handle, 20, ref dark, sizeof(int));
        }
        catch
        {
            // 非 Win11 或 dwmapi 不可用时退化为直角窗口，不影响功能
        }
    }

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
        {
            ToggleMaximize();
            return;
        }

        if (e.LeftButton != MouseButtonState.Pressed) return;

        if (WindowState == WindowState.Maximized)
        {
            // ⚠️ 窗口最大化时调用 DragMove() 会抛 InvalidOperationException。
            //    原先把异常 catch 掉了，结果就是"全屏之后拖不动"（看起来像没反应）。
            //
            //    按 Windows 的标准手感处理：先还原成普通窗口，并让鼠标**仍然抓在标题栏上
            //    对应的横向比例位置**，然后再接着拖 —— 否则窗口会瞬移一下，很难用。
            //
            // ⚠️⚠️ **单位陷阱**：PointToScreen 返回的是**物理像素**，
            //      而 Left/Top/Width/ActualWidth/RestoreBounds 全是 **DIP**（与 DPI 无关）。
            //      两者只在 100% 缩放下相等 —— 在 125% / 150% 缩放的屏幕上直接混算，
            //      窗口会飞出去一大截（实测反馈：1080p 笔记本上尤其明显）。
            //      所以这里先用 VisualTreeHelper.GetDpi 把物理像素换算成 DIP 再参与计算。
            DpiScale dpi = VisualTreeHelper.GetDpi(this);

            Point pointerOnScreen = PointToScreen(e.GetPosition(this));   // 物理像素
            Point pointerInWindow = e.GetPosition(this);                  // DIP（相对窗口）
            Rect restore = RestoreBounds;                                 // DIP（还原后的边界）

            double pointerDipX = pointerOnScreen.X / dpi.DpiScaleX;
            double pointerDipY = pointerOnScreen.Y / dpi.DpiScaleY;

            // 鼠标落在标题栏的横向比例；窗口越宽，还原后越该按比例对齐，手感才自然
            double horizontalRatio = ActualWidth <= 0
                ? 0.5
                : Math.Clamp(pointerInWindow.X / ActualWidth, 0, 1);

            ToggleMaximize();
            UpdateLayout();

            double restoredWidth = restore.Width > 0 ? restore.Width : Width;
            Left = pointerDipX - restoredWidth * horizontalRatio;
            Top = Math.Max(0, pointerDipY - pointerInWindow.Y);
        }

        try
        {
            DragMove();
        }
        catch
        {
            // 拖动过程中鼠标释放可能抛异常，忽略
        }
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void Maximize_Click(object sender, RoutedEventArgs e) => ToggleMaximize();

    private void ToggleMaximize()
    {
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        MaximizeIcon.Data = (Geometry)FindResource(
            WindowState == WindowState.Maximized ? "Icon.Restore" : "Icon.Maximize");
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void Theme_Click(object sender, RoutedEventArgs e)
    {
        ThemeManager.Toggle();
        UpdateThemeIcon();
        ApplyWindowChromeTweaks();
        HexView.InvalidateVisual();
    }

    private void UpdateThemeIcon()
    {
        if (ThemeButton.Content is not System.Windows.Shapes.Path path) return;
        path.Data = (Geometry)FindResource(ThemeManager.IsDark ? "Icon.Sun" : "Icon.Moon");
    }

    // ── 视图切换 ───────────────────────────────────────────────────────────

    private void ViewTab_Checked(object sender, RoutedEventArgs e)
    {
        if (sender is not RadioButton { Tag: string tag }) return;
        SetPanelVisibility(tag);

        // 切到「编码」页就直接对当前选区做一次识别：这一步本来就是用户切页的目的，
        // 没必要再多点一次按钮（选区变了再切回来也会重新分析）。
        if (tag == "Codec") _viewModel.AnalyzeSelectionAsCodec();
    }

    private void SetPanelVisibility(string tag)
    {
        if (PanelHex is null) return;   // 初始化早期可能尚未构建

        PanelHex.Visibility = tag == "Hex" ? Visibility.Visible : Visibility.Collapsed;
        PanelStructure.Visibility = tag == "Structure" ? Visibility.Visible : Visibility.Collapsed;
        PanelStego.Visibility = tag == "Stego" ? Visibility.Visible : Visibility.Collapsed;
        PanelStrings.Visibility = tag == "Strings" ? Visibility.Visible : Visibility.Collapsed;
        PanelCodec.Visibility = tag == "Codec" ? Visibility.Visible : Visibility.Collapsed;
        PanelEntropy.Visibility = tag == "Entropy" ? Visibility.Visible : Visibility.Collapsed;
    }

    private void SwitchToHexView()
    {
        TabHex.IsChecked = true;
        SetPanelVisibility("Hex");
    }

    // ── 编码识别（复用隔壁 Coding\ctfcodec）──────────────────────────────

    private void AnalyzeCodec_Click(object sender, RoutedEventArgs e)
        => _viewModel.AnalyzeSelectionAsCodec();

    private void DecodeSuggestion_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string algorithm } || string.IsNullOrWhiteSpace(algorithm)) return;
        _viewModel.DecodeSelectionWith(algorithm);
    }

    private void SaveDecoded_Click(object sender, RoutedEventArgs e) => _viewModel.SaveDecodedResult();

    private async void OpenDecoded_Click(object sender, RoutedEventArgs e)
        => await _viewModel.OpenDecodedAsDocumentAsync();

    // ── 文档与分析联动 ─────────────────────────────────────────────────────

    private void OnDocumentReplaced()
    {
        HexView.Document = _viewModel.Document;
        HexView.EntropyBlocks = [];
        HexView.SearchHits = [];
        HexView.Highlights = [];
        SyncScrollBar();
        Title = _viewModel.TitleText;

        // 打开文件后直接把焦点交给十六进制视图，可以直接开始键入
        HexView.Focus();
    }

    private void OnDocumentContentChanged()
    {
        HexView.EntropyBlocks = _viewModel.EntropyBlocks;
        HexView.SearchHits = _viewModel.SearchHits;
        HexView.Highlights = BuildHighlights();
        HexView.AttentionHighlights = BuildAttentionHighlights();
        HexView.StructureHighlights = BuildStructureHighlights();
        HexView.InvalidateVisual();
        SyncScrollBar();
        Title = _viewModel.TitleText;

        // 空状态提示
        StegoEmptyHint.Visibility = _viewModel.HasLsbHits ? Visibility.Collapsed : Visibility.Visible;
        StringsEmptyHint.Visibility = _viewModel.Strings.Count > 0 ? Visibility.Collapsed : Visibility.Visible;

        // 文档刚就绪（或重新分析完）时，若正停在「编码」页就补跑一次识别。
        // 否则 --view=codec 启动会停在"尚未打开文件"——切页发生在加载文件之前。
        if (PanelCodec.Visibility == Visibility.Visible) _viewModel.AnalyzeSelectionAsCodec();

        // --select=偏移,长度：文档就绪后自动选中该区间，
        // 顺带触发「选中即识别」，让脚本/截图也能拿到识别结论。
        if (!_startupSelectionApplied && App.StartupSelection is { } selection && _viewModel.Document is not null)
        {
            _startupSelectionApplied = true;
            SwitchToHexView();

            // 必须等布局完成再居中：否则 VisibleLineCount 还是 0/旧值，
            // 算出来的首行是错的（表现为目标跑到视野外）。
            _ = Dispatcher.BeginInvoke(new Action(() =>
            {
                HexView.RevealRangeCentered(selection.Offset, selection.Length);
            }), System.Windows.Threading.DispatcherPriority.Loaded);
        }
    }

    /// <summary>需要特别注意的那一类（可疑载荷 / 关键线索）—— 统一标红。</summary>
    private static readonly Color AttentionColor = Color.FromRgb(0xC0, 0x50, 0x4D);

    /// <summary>
    /// 每个关键区域**只标开头这么多字节**。
    ///
    /// 为什么不整段染色：一个 ZIP 条目动辄几百字节，整段铺色等于在屏幕上糊一大片，
    /// 真正要看的"起点"反而被淹没。标记的职责是**指出位置**，不是覆盖全部内容。
    /// </summary>
    private const int MarkHeadBytes = 16;

    /// <summary>
    /// 值得标记的结构类别 —— **只标关键位置**。
    ///
    /// 要求是"将比较重要的进行标记，比方说文件头、起始位置"。
    /// 因此刻意排除 Content（占大头的数据本身）、Padding（填充）、Code/Resource（大段内容）：
    /// 它们没有"位置"价值，标上去只会稀释信号。每个类别一种颜色，便于一眼分类。
    /// </summary>
    private static bool IsKeyRegion(HexLens.Core.Formats.StructureCategory category)
        => category is HexLens.Core.Formats.StructureCategory.FileHeader      // 文件签名（起始）
            or HexLens.Core.Formats.StructureCategory.FormatHeader            // 格式头（IHDR / PE 头…）
            or HexLens.Core.Formats.StructureCategory.Table                   // 节表 / 中央目录 / EOCD
            or HexLens.Core.Formats.StructureCategory.Metadata                // 元数据 / 注释
            or HexLens.Core.Formats.StructureCategory.Overlay;                // 尾部附加

    /// <summary>关键位置标记：每类一种颜色，且只覆盖区域开头的十几字节。</summary>
    private List<HexHighlight> BuildHighlights()
    {
        var highlights = new List<HexHighlight>();

        foreach (HexLens.Core.Formats.StructureRegion region in _viewModel.StructureRegions)
        {
            if (!IsKeyRegion(region.Category)) continue;

            highlights.Add(new HexHighlight(
                region.Offset,
                Math.Min(region.Length, MarkHeadBytes),
                CategoryColor(region.Category),
                $"{region.Name}　0x{region.Offset:X} 起（共 {region.Length:N0} 字节）"));
        }

        return highlights;
    }

    /// <summary>
    /// 需要**特别注意**的区间（可疑载荷 / 关键线索）—— 标红。
    /// 同样只标开头一小段：红色要"跳出来"，铺满几百字节就失去作用了。
    /// </summary>
    private List<HexHighlight> BuildAttentionHighlights()
    {
        var marks = new List<HexHighlight>();

        // ① 可疑载荷
        foreach (CarvedFileItem file in _viewModel.Files)
        {
            if (file.Source.Offset == 0) continue;                    // 主文件本身不标

            marks.Add(new HexHighlight(
                file.Source.Offset,
                Math.Min(file.Source.Length, MarkHeadBytes),
                AttentionColor,
                $"⚠ {file.Name}　0x{file.Source.Offset:X} 起（{file.Source.SizeText}）· {file.PositionText}"));
        }

        // ② 关键线索
        foreach (ClueItem clue in _viewModel.Clues)
        {
            if (clue.Source.Kind is not (ClueKind.TrailingData or ClueKind.Base64Blob or ClueKind.HighEntropyRegion)) continue;
            if (clue.Source.Length <= 0) continue;

            marks.Add(new HexHighlight(
                clue.Source.Offset,
                Math.Min(clue.Source.Length, MarkHeadBytes),
                AttentionColor,
                $"⚠ 线索：{clue.Title}"));
        }

        return marks;
    }

    /// <summary>结构区域 → 底部结构条的分段色块（带悬停说明）。</summary>
    private List<HexHighlight> BuildStructureHighlights()
    {
        var list = new List<HexHighlight>();

        foreach (HexLens.Core.Formats.StructureRegion region in _viewModel.StructureRegions)
        {
            if (region.Category == HexLens.Core.Formats.StructureCategory.Unknown) continue;

            list.Add(new HexHighlight(
                region.Offset,
                region.Length,
                CategoryColor(region.Category),
                $"{region.Name}　0x{region.Offset:X} – 0x{region.End:X}（{region.Length:N0} 字节）"));
        }

        return list;
    }

    /// <summary>
    /// 结构类别 → 着色。一律取**浅色**：
    /// 纸白底上深色会喧宾夺主，浅色既能区分分区，又不压过内容本身。
    /// （红留给了"需要注意"的可疑/线索，所以这里刻意不用正红。）
    /// </summary>
    private static Color CategoryColor(HexLens.Core.Formats.StructureCategory category) => category switch
    {
        HexLens.Core.Formats.StructureCategory.FileHeader => Color.FromRgb(0x5A, 0x8F, 0x6B),     // 浅竹绿
        HexLens.Core.Formats.StructureCategory.FormatHeader => Color.FromRgb(0x6B, 0xA8, 0x7C),   // 浅绿
        HexLens.Core.Formats.StructureCategory.Metadata => Color.FromRgb(0x6F, 0xA8, 0xCC),       // 浅蓝
        HexLens.Core.Formats.StructureCategory.Palette => Color.FromRgb(0x9B, 0x86, 0xC4),        // 浅紫
        HexLens.Core.Formats.StructureCategory.Table => Color.FromRgb(0xC9, 0xA2, 0x27),          // 浅琥珀
        HexLens.Core.Formats.StructureCategory.Code => Color.FromRgb(0xD9, 0x8A, 0x6B),           // 浅橙
        HexLens.Core.Formats.StructureCategory.Resource => Color.FromRgb(0x4F, 0xA8, 0xA8),       // 浅青
        HexLens.Core.Formats.StructureCategory.Content => Color.FromRgb(0x8F, 0xB8, 0x9B),        // 浅竹（实际不参与染色）
        HexLens.Core.Formats.StructureCategory.Footer => Color.FromRgb(0x9A, 0x9A, 0x90),         // 浅灰
        HexLens.Core.Formats.StructureCategory.Overlay => AttentionColor,                          // 可疑 → 红
        HexLens.Core.Formats.StructureCategory.Padding => Color.FromRgb(0xA8, 0xA8, 0xA0),        // 浅灰
        _ => Colors.Transparent,
    };

    private void SyncScrollBar()
    {
        int totalLines = HexView.TotalLines;
        int visible = HexView.VisibleLineCount;
        int scrollRange = Math.Max(1, totalLines - visible);

        // 滑块高度是按 ViewportSize / 总行数 算的，文件一大就扁成一条（实测只剩 9px）。
        // ⚠️ 在 Thumb 的模板里加 MinHeight **没用** —— WPF 的 Track 自己算尺寸并裁切内容，
        //    试过"溢出显示"也无效（实测仍是 12px）。所以唯一能调的就是 ViewportSize。
        //
        // 但 ViewportSize 一虚高，Maximum 就得跟着变小，直接用 Value 当行号就会"滑块到底、文件没到底"。
        // 解法：**ViewportSize 只管外观，Value ↔ 行号走比例映射**。
        //   滑块高度 = 轨道高 × ViewportSize / 总行数 → 钳到 1/12 后约 60px，好看也好抓；
        //   拖到底（Value = Maximum）经比例换算正好落在最后一行 → 文件真的到底。
        // 滑块的长度按文件规模**分档递减**：
        //   文件不长时（totalLines/12 已经小于可见行数）由 visible 兜底 → 就是真实比例，滑块自然就长；
        //   文件很长时把它缩短，免得一条滑块占掉 1/12 的视觉高度；
        //   但也不能无限缩 —— 最大档约 1/40（约 20px），再短就又回到"抓不住"。
        int divisor = totalLines switch
        {
            < 400_000 => 12,        // 约 6 MB 以内
            < 4_000_000 => 24,      // 约 64 MB 以内
            _ => 40,                // 更大
        };

        int sliderViewport = Math.Max(visible, Math.Max(1, totalLines / divisor));

        // 整段都要抑制回调：设置 Maximum / ViewportSize / LargeChange 时，
        // WPF 的 ScrollBar 会顺带调整 Value 并触发 ValueChanged，
        // 若不屏蔽就会被当成"用户滚动"，把视图莫名其妙地滚走
        //（实测表现为：打开文件后视图停在 0x210 而不是开头）。
        _syncingScroll = true;
        try
        {
            HexScrollBar.Maximum = Math.Max(1, totalLines - sliderViewport);
            HexScrollBar.ViewportSize = sliderViewport;
            HexScrollBar.LargeChange = Math.Max(1, visible);
            HexScrollBar.SmallChange = 1;

            // 行号 → 滑块位置（按比例）
            HexScrollBar.Value = HexView.FirstVisibleLine / (double)scrollRange * HexScrollBar.Maximum;
        }
        finally
        {
            _syncingScroll = false;
        }
    }

    private bool _syncingScroll;

    private void HexScrollBar_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (_syncingScroll) return;
        _syncingScroll = true;
        try
        {
            // 滑块位置 → 行号（与 SyncScrollBar 里的比例映射互为逆运算）——
            // 这一步是"拖到底就能到文件末尾"的关键。
            int totalLines = HexView.TotalLines;
            int visible = HexView.VisibleLineCount;
            int scrollRange = Math.Max(0, totalLines - visible);

            double ratio = HexScrollBar.Maximum <= 0 ? 0 : e.NewValue / HexScrollBar.Maximum;
            HexView.SetFirstVisibleLine((int)Math.Round(ratio * scrollRange));
        }
        finally
        {
            _syncingScroll = false;
        }
    }

    // ── 线索交互 ───────────────────────────────────────────────────────────

    /// <summary>跑单字节 XOR 暴力破解（结果列在「编码」页左栏下方）。</summary>
    private void BruteForceXor_Click(object sender, RoutedEventArgs e) => _viewModel.BruteForceXor();

    /// <summary>把某个 XOR 候选的密钥应用到它记录的区间。</summary>
    private void ApplyXorKey_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { CommandParameter: XorCandidateItem item }) return;
        _viewModel.ApplyXorKey(item);
    }

    /// <summary>
    /// 点击线索卡片上的「应用修复」。
    ///
    /// 之所以单独一个入口而不是复用选区动作：它**会真的改文档**，
    /// 所以必须只有在线索明确给出 Payload 时才执行，不能靠"当前选中的线索"猜。
    /// </summary>
    private void ApplyFix_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { CommandParameter: ClueItem item }) return;
        if (item.FixAction is not { } fix) return;

        _viewModel.ExecuteClueAction(fix);
    }

    private void ClueList_SelectionChanged(object sender, SelectionChangedEventArgs e)    {
        if (ClueList.SelectedItem is not ClueItem clue) return;

        _viewModel.StatusMessage = clue.Actions.Count > 0
            ? $"选中线索：{clue.Title}｜双击执行「{clue.Actions[0].Label}」"
            : $"选中线索：{clue.Title}";

        // 单击线索即把对应区间滚到十六进制视图**垂直中央**。
        // 旧行为是单击只改状态栏文字、必须双击才定位 —— 点了像没反应，
        // 而线索本来就是"我要去看这段数据"的入口。
        SwitchToHexView();
        HexView.RevealRangeCentered(clue.Source.Offset, clue.Source.Length);
    }

    private void ClueList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (ClueList.SelectedItem is not ClueItem clue) return;

        // 优先导出，其次定位
        ClueAction? action = clue.Actions.FirstOrDefault(static a => a.Kind == ClueActionKind.ExtractRange)
                             ?? clue.Actions.FirstOrDefault();

        if (action is not null) _viewModel.ExecuteClueAction(action);
    }

    private void ClueFilter_TextChanged(object sender, TextChangedEventArgs e)
    {
        string filter = ClueFilterBox.Text.Trim();
        ClueFilterPlaceholder.Visibility = filter.Length == 0 ? Visibility.Visible : Visibility.Collapsed;

        var view = System.Windows.Data.CollectionViewSource.GetDefaultView(ClueList.ItemsSource);
        view.Filter = string.IsNullOrEmpty(filter)
            ? null
            : item => item is ClueItem clue
                      && (clue.Title.Contains(filter, StringComparison.OrdinalIgnoreCase)
                          || clue.Detail.Contains(filter, StringComparison.OrdinalIgnoreCase)
                          || clue.KindText.Contains(filter, StringComparison.OrdinalIgnoreCase));
    }

    // ── 字符串交互 ─────────────────────────────────────────────────────────

    /// <summary>
    /// 字符串列表：单击任意一行即复制该字符串。
    ///
    /// 为什么不靠"选中文本框里的文字复制"：ListBoxItem 为了拖拽选择会在
    /// PreviewMouseLeftButtonDown 阶段把鼠标捕获走，子 TextBox 根本收不到点击，
    /// 用户看到的就是"选不中、复制不了"。所以这里给出不依赖文本选择的复制入口。
    /// </summary>
    private void StringList_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (StringList.SelectedItem is StringItem item)
        {
            CopyToClipboard(item.Text, $"已复制字符串（{item.Text.Length} 字符）");
        }
    }

    /// <summary>右键时先把鼠标所指的那一行选中，菜单里的「复制这一行」才有明确对象。</summary>
    private void StringList_MouseRightButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (ItemsControl.ContainerFromElement(StringList, (DependencyObject)e.OriginalSource) is ListBoxItem row
            && row.DataContext is StringItem item)
        {
            StringList.SelectedItem = item;
        }
    }

    private void StringCopyRow_Click(object sender, RoutedEventArgs e)
    {
        if (StringList.SelectedItem is StringItem item)
        {
            CopyToClipboard(item.Text, "已复制该字符串");
        }
        else
        {
            _viewModel.Notify("请先选中一行字符串");
        }
    }

    private void StringCopyAll_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel.Strings.Count == 0)
        {
            _viewModel.Notify("当前没有提取到字符串");
            return;
        }

        var builder = new System.Text.StringBuilder();
        foreach (StringItem item in _viewModel.Strings)
        {
            if (builder.Length > 0) builder.AppendLine();
            builder.Append(item.Text);
        }

        CopyToClipboard(builder.ToString(), $"已复制全部 {_viewModel.Strings.Count} 条字符串");
    }

    private void CopyToClipboard(string text, string message)
    {
        if (string.IsNullOrEmpty(text))
        {
            _viewModel.Notify("内容为空，未复制");
            return;
        }

        try
        {
            Clipboard.SetText(text);
            _viewModel.Notify(message);
        }
        catch (Exception ex)
        {
            _viewModel.Notify($"复制失败：{ex.Message}");
        }
    }

    private void StringList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (StringList.SelectedItem is not StringItem item) return;
        SwitchToHexView();
        HexView.RevealRange(item.Source.Offset, item.Source.ByteLength);
    }

    // ── 搜索 ───────────────────────────────────────────────────────────────

    private void SearchMode_Click(object sender, RoutedEventArgs e)
    {
        _searchModeIndex = (_searchModeIndex + 1) % 3;
        _viewModel.SearchModeIndex = _searchModeIndex;
        UpdateSearchModeButton();
    }

    private void UpdateSearchModeButton()
    {
        SearchModeButton.Content = _searchModeIndex switch
        {
            1 => "文本",
            2 => "正则",
            _ => "HEX",
        };
    }

    private void SearchBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter) return;
        _viewModel.SearchPattern = SearchBox.Text;
        _viewModel.SearchCommand.Execute(null);
        e.Handled = true;
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        SearchPlaceholder.Visibility = SearchBox.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void Search_Click(object sender, RoutedEventArgs e)
    {
        _viewModel.SearchPattern = SearchBox.Text;
        _viewModel.SearchCommand.Execute(null);
    }

    // ── 工具条 ─────────────────────────────────────────────────────────────

    private async void Open_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "打开待分析的文件",
            Filter = "所有文件 (*.*)|*.*",
            CheckFileExists = true,
        };

        if (dialog.ShowDialog() == true) await _viewModel.OpenPathAsync(dialog.FileName);
    }

    private async void Analyze_Click(object sender, RoutedEventArgs e) => await _viewModel.AnalyzeAsync();

    private void Save_Click(object sender, RoutedEventArgs e) => _viewModel.SaveCommand.Execute(null);

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        base.OnClosing(e);
        _viewModel.CleanupOnClose();          // 删掉隐藏工作副本，不留垃圾
    }

    private void SaveAs_Click(object sender, RoutedEventArgs e) => _viewModel.SaveAsCommand.Execute(null);

    private void Undo_Click(object sender, RoutedEventArgs e)
    {
        _viewModel.UndoCommand.Execute(null);
        HexView.InvalidateVisual();
    }

    private void Redo_Click(object sender, RoutedEventArgs e)
    {
        _viewModel.RedoCommand.Execute(null);
        HexView.InvalidateVisual();
    }

    // ── 拖放 ───────────────────────────────────────────────────────────────

    /// <summary>
    /// 当前是否以管理员身份运行。
    ///
    /// 为什么要检测：Windows 的 **UIPI（用户界面特权隔离）**不允许普通进程（资源管理器）
    /// 向管理员进程拖放文件 —— 表现是鼠标变成"禁止"光标、拖放完全无反应，
    /// 而且拦在系统层，`DragOver` 都没机会执行。
    /// 这是系统安全设计而非程序缺陷，但用户不知道就会当成 bug，所以要主动说清楚。
    /// </summary>
    private static bool IsRunningElevated()
    {
        try
        {
            using System.Security.Principal.WindowsIdentity identity =
                System.Security.Principal.WindowsIdentity.GetCurrent();

            return new System.Security.Principal.WindowsPrincipal(identity)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private void Window_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private async void Window_Drop(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;
        if (e.Data.GetData(DataFormats.FileDrop) is not string[] files || files.Length == 0) return;

        await _viewModel.OpenPathAsync(files[0]);
    }

    // ── 快捷键 ─────────────────────────────────────────────────────────────

    private async void OnPreviewKeyDown(object sender, KeyEventArgs e)
    {
        bool control = Keyboard.Modifiers.HasFlag(ModifierKeys.Control);

        if (control && e.Key == Key.O)
        {
            Open_Click(sender, e);
            e.Handled = true;
            return;
        }

        if (control && e.Key == Key.S)
        {
            _viewModel.SaveCommand.Execute(null);
            e.Handled = true;
            return;
        }

        if (control && e.Key == Key.Z)
        {
            _viewModel.UndoCommand.Execute(null);
            HexView.InvalidateVisual();
            e.Handled = true;
            return;
        }

        if (control && e.Key == Key.Y)
        {
            _viewModel.RedoCommand.Execute(null);
            HexView.InvalidateVisual();
            e.Handled = true;
            return;
        }

        if (control && e.Key == Key.F)
        {
            SearchBox.Focus();
            SearchBox.SelectAll();
            e.Handled = true;
            return;
        }

        if (e.Key == Key.F5)
        {
            await _viewModel.AnalyzeAsync();
            e.Handled = true;
        }
    }
}
