using System.Globalization;
using System.Text;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using HexLens.Core.Analysis;
using HexLens.Core.Documents;

namespace HexLens.App.Controls;

/// <summary>十六进制视图里的区间高亮（标注结构区域、发现的载荷、线索、搜索命中）。</summary>
/// <param name="Offset">起点。</param>
/// <param name="Length">长度。</param>
/// <param name="Color">填充色（绘制时统一用低透明度，避免盖住字节本身）。</param>
/// <param name="Label">悬停提示文本（null 表示该区间不提示）。</param>
/// <param name="Alpha">填充不透明度：结构区域用较低值（不抢字节），可疑载荷用较高值。</param>
public sealed record HexHighlight(int Offset, int Length, Color Color, string? Label = null, byte Alpha = 0x5A);

/// <summary>
/// 虚拟化十六进制视图：只绘制可见行，支持光标/选区/半字节编辑/复制粘贴，
/// 顶部还有一条熵色带（一眼看出数据里哪段是压缩或加密的）。
/// </summary>
public sealed class HexEditorView : FrameworkElement
{
    /// <summary>每行字节数。</summary>
    public const int BytesPerLine = 16;

    private const double EntropyStripHeight = 16;

    /// <summary>底部结构条高度。</summary>
    private const double StructureStripHeight = 19;
    private const double HeaderHeight = 22;
    private const double LeftPadding = 14;
    private const double ColumnGap = 14;

    private ByteDocument? _document;
    private Typeface _typeface = new("Consolas");
    private double _charWidth = 7.2;
    private double _lineHeight = 18;
    private bool _metricsReady;
    private int _nibble;

    /// <summary>
    /// 光标是否停在 ASCII 列。决定键盘输入是"直接写字节"还是"改半字节"。
    /// 点击哪一列就切到哪一列；跳转（RevealRange）默认回到十六进制列。
    /// </summary>
    private bool _caretOnAscii;
    private string? _hoverLabel;

    public HexEditorView()
    {
        Focusable = true;
        FocusVisualStyle = null;
        ClipToBounds = true;
        Cursor = Cursors.IBeam;

        // 右键菜单：把"复制文本"和"复制字节"都摆出来。
        // 之前 Ctrl+C 只会复制十六进制，想拿那段 ASCII 文本就没有任何入口。
        var menu = new System.Windows.Controls.ContextMenu();
        menu.Items.Add(MakeMenuItem("复制文本", CopySelectionSmart));
        menu.Items.Add(MakeMenuItem("复制十六进制", CopySelectionAsHex));
        menu.Items.Add(MakeMenuItem("复制为 C 数组", CopySelectionAsCArray));
        menu.Items.Add(MakeMenuItem("复制为 Python bytes", CopySelectionAsPython));
        menu.Items.Add(new System.Windows.Controls.Separator());
        menu.Items.Add(MakeMenuItem("全选", SelectAllBytes));
        ContextMenu = menu;
    }

    private static System.Windows.Controls.MenuItem MakeMenuItem(string header, Action action)
    {
        var item = new System.Windows.Controls.MenuItem { Header = header };
        item.Click += (_, _) => action();
        return item;
    }

    /// <summary>光标位置或选区变化。</summary>
    public event EventHandler? CaretMoved;

    /// <summary>内容被编辑。</summary>
    public event EventHandler? ContentEdited;

    /// <summary>可见范围变化（外部据此更新滚动条）。</summary>
    public event EventHandler? ScrollInfoChanged;

    /// <summary>当前文档。</summary>
    public ByteDocument? Document
    {
        get => _document;
        set
        {
            _document = value;
            FirstVisibleLine = 0;
            _nibble = 0;
            CaretOffset = 0;
            SelectionAnchor = 0;
            InvalidateVisual();
            ScrollInfoChanged?.Invoke(this, EventArgs.Empty);
            CaretMoved?.Invoke(this, EventArgs.Empty);
        }
    }

    /// <summary>熵剖面（画顶部色带）。</summary>
    public IReadOnlyList<EntropyBlock> EntropyBlocks { get; set; } = [];

    /// <summary>搜索命中（黄绿底）。</summary>
    public IReadOnlyList<SearchHit> SearchHits { get; set; } = [];

    /// <summary>区间高亮（标注发现的可疑载荷）。</summary>
    public IReadOnlyList<HexHighlight> Highlights { get; set; } = [];

    /// <summary>结构区域（在底部结构条上按类别分段显示）。</summary>
    public IReadOnlyList<HexHighlight> StructureHighlights { get; set; } = [];

    /// <summary>
    /// **需要注意**的区间（可疑载荷 / 关键线索）。
    /// 与 Highlights 分成两层而不是混在一个列表里：靠"谁后加入谁覆盖"来定优先级太脆弱，
    /// 一旦顺序变了红色就会被浅色结构标记盖掉（实测踩过）。
    /// </summary>
    public IReadOnlyList<HexHighlight> AttentionHighlights { get; set; } = [];

    /// <summary>光标偏移。</summary>
    public int CaretOffset { get; private set; }

    /// <summary>选区锚点。</summary>
    public int SelectionAnchor { get; private set; }

    /// <summary>选区起点。</summary>
    public int SelectionStart => Math.Min(CaretOffset, SelectionAnchor);

    /// <summary>选区长度。</summary>
    public int SelectionLength => Math.Abs(CaretOffset - SelectionAnchor);

    /// <summary>当前首行。</summary>
    public int FirstVisibleLine { get; private set; }

    /// <summary>总行数。</summary>
    public int TotalLines => _document is null ? 0 : (_document.Length + BytesPerLine - 1) / BytesPerLine;

    /// <summary>可见行数（要扣掉底部结构条，否则最后几行会被它遮住）。</summary>
    public int VisibleLineCount => _lineHeight <= 0
        ? 1
        : Math.Max(1, (int)((ActualHeight - EntropyStripHeight - HeaderHeight - StructureStripHeight) / _lineHeight));

    /// <summary>等宽字符宽度（按当前 DPI 实测）。</summary>
    public double CharacterWidth
    {
        get
        {
            EnsureMetrics();
            return _charWidth;
        }
    }

    /// <summary>行高（按当前 DPI 实测）。</summary>
    public double LineHeight
    {
        get
        {
            EnsureMetrics();
            return _lineHeight;
        }
    }

    /// <summary>滚动到指定偏移并选中区间。</summary>
    public void RevealRange(int offset, int length)
    {
        if (_document is null) return;

        CaretOffset = Math.Clamp(offset, 0, Math.Max(0, _document.Length - 1));
        SelectionAnchor = length > 1
            ? Math.Clamp(offset + length, 0, _document.Length)
            : CaretOffset;

        _nibble = 0;
        CaretOnAscii = false;       // 跳转后默认回到十六进制列（顺带恢复输入法）
        EnsureCaretVisible();
        InvalidateVisual();
        CaretMoved?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// 滚动到指定偏移并选中，且让目标落在视图**垂直中央**。
    ///
    /// 为什么与 RevealRange 分开：EnsureCaretVisible 只保证"可见"，
    /// 目标停在顶边或底边时，前后文都看不到，还得手动滚一下。
    /// 线索是"我要去看这段数据"的入口，居中才是它该有的行为。
    /// </summary>
    public void RevealRangeCentered(int offset, int length)
    {
        RevealRange(offset, length);
        if (_document is null || _document.Length == 0) return;

        int targetLine = Math.Clamp(offset, 0, _document.Length - 1) / BytesPerLine;
        SetFirstVisibleLine(targetLine - VisibleLineCount / 2);
    }

    /// <summary>设置首行（供外部滚动条使用）。</summary>
    public void SetFirstVisibleLine(int line)
    {
        int max = Math.Max(0, TotalLines - VisibleLineCount);
        int clamped = Math.Clamp(line, 0, max);
        if (clamped == FirstVisibleLine) return;
        FirstVisibleLine = clamped;
        InvalidateVisual();
        ScrollInfoChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>复制选中区间为十六进制文本。</summary>
    public void CopySelectionAsHex() => SetClipboard(BuildHexText());

    /// <summary>
    /// 智能复制：选区看起来是文本（可打印比例 ≥ 90%）就复制文本，否则复制十六进制。
    ///
    /// 十六进制编辑器里"我要那串字符"和"我要那些字节"都是常见需求，
    /// 让内容自己决定默认值，比硬编码一种更不容易出错。
    /// </summary>
    public void CopySelectionSmart()
    {
        byte[] data = GetSelectionBytes();
        if (data.Length == 0) return;

        int printable = 0;
        foreach (byte b in data)
        {
            if (b is >= 0x20 and < 0x7F || b is 0x09 or 0x0A or 0x0D) printable++;
        }

        if (printable * 100 / data.Length >= 90) CopySelectionAsText();
        else CopySelectionAsHex();
    }

    /// <summary>取出选区字节；没有选区时取光标处的单个字节。</summary>
    private byte[] GetSelectionBytes()
    {
        if (_document is null || _document.Length == 0) return [];

        int start = SelectionLength > 0 ? SelectionStart : CaretOffset;
        int length = SelectionLength > 0 ? SelectionLength : 1;
        if (start < 0 || start >= _document.Length) return [];

        return _document.ReadRange(start, Math.Min(length, _document.Length - start));
    }

    /// <summary>复制选中区间为 ASCII 文本。</summary>
    public void CopySelectionAsText() => SetClipboard(BuildAsciiText());

    /// <summary>复制为 C 数组字面量。</summary>
    public void CopySelectionAsCArray() => SetClipboard(BuildCArrayText());

    /// <summary>复制为 Python bytes 字面量。</summary>
    public void CopySelectionAsPython() => SetClipboard(BuildPythonText());

    /// <summary>把剪贴板内容（十六进制或文本）写入当前光标处。</summary>
    public void PasteFromClipboard()
    {
        if (_document is null) return;

        string text;
        try
        {
            text = Clipboard.GetText();
        }
        catch
        {
            return;
        }
        if (string.IsNullOrEmpty(text)) return;

        byte[] payload = ParseHexOrText(text);
        if (payload.Length == 0) return;

        _document.Overwrite(CaretOffset, payload);
        CaretOffset += payload.Length;
        SelectionAnchor = CaretOffset;
        _nibble = 0;
        AfterEdit();
    }

    /// <summary>删除选中字节（或光标处的 1 个字节）。</summary>
    public void DeleteSelection()
    {
        if (_document is null) return;

        int start = SelectionLength > 0 ? SelectionStart : CaretOffset;
        int count = SelectionLength > 0 ? SelectionLength : 1;
        if (start >= _document.Length || count <= 0) return;

        _document.Remove(start, Math.Min(count, _document.Length - start));
        CaretOffset = Math.Min(start, Math.Max(0, _document.Length - 1));
        SelectionAnchor = CaretOffset;
        _nibble = 0;
        AfterEdit();
    }

    /// <summary>在光标处写入一个字节（覆盖模式）。</summary>
    public void WriteByte(byte value)
    {
        if (_document is null) return;

        if (CaretOffset >= _document.Length)
        {
            _document.Append([value]);
        }
        else
        {
            _document.Overwrite(CaretOffset, [value]);
        }

        CaretOffset = Math.Min(CaretOffset + 1, Math.Max(0, _document.Length - 1));
        SelectionAnchor = CaretOffset;
        _nibble = 0;
        AfterEdit();
    }

    /// <summary>
    /// 在光标处**插入**一个字节，后面的内容整体后移。
    ///
    /// 与十六进制列的"覆盖"刻意不同：半字节编辑天然是覆盖语义（改的就是那半个字节），
    /// 而在 ASCII 列打字更像是"往这里塞一个字符" —— 覆盖会把后面的内容冲掉，那是错的。
    /// </summary>
    public void InsertByte(byte value)
    {
        if (_document is null) return;

        _document.Insert(CaretOffset, [value]);
        CaretOffset = Math.Min(CaretOffset + 1, Math.Max(0, _document.Length - 1));
        SelectionAnchor = CaretOffset;
        _nibble = 0;
        AfterEdit();
    }

    protected override void OnRender(DrawingContext dc)
    {
        var background = TryFindBrush("WindowBackgroundBrush", Color.FromRgb(0xF6, 0xF3, 0xEC));
        dc.DrawRectangle(background, null, new Rect(RenderSize));

        EnsureMetrics();

        if (_document is null)
        {
            DrawPlaceholder(dc);
            return;
        }

        DrawEntropyStrip(dc);
        DrawHeaderRow(dc);
        DrawByteRows(dc);
        DrawStructureStrip(dc);
    }

    /// <summary>
    /// 底部结构条：把识别出的文件结构（PE 的 DOS头/PE头/节表/各节、PNG 的块、ZIP 条目…）
    /// 按类别画成一条分段色带。
    ///
    /// 为什么不只靠字节底色：底色受字节内容干扰、透明度一高就盖住数据、一低就看不见；
    /// 分段条则能让"这个文件由哪些部分构成"一眼可见 —— 这正是结构标识的用途。
    /// </summary>
    private void DrawStructureStrip(DrawingContext dc)
    {
        double stripTop = ActualHeight - StructureStripHeight;
        if (stripTop <= 0 || _document is null || _document.Length == 0) return;

        Brush background = TryFindBrush("PaperWarmBrush", Color.FromRgb(0xF0, 0xEB, 0xE0));
        dc.DrawRectangle(background, null, new Rect(0, stripTop, ActualWidth, StructureStripHeight));

        var border = new Pen(TryFindBrush("BorderSubtleBrush", Colors.LightGray), 1);
        dc.DrawLine(border, new Point(0, stripTop + 0.5), new Point(ActualWidth, stripTop + 0.5));

        if (StructureHighlights.Count == 0)
        {
            dc.DrawText(MakeText("未识别出可划分的结构区域", TryFindBrush("InkGhostBrush", Colors.Gray), 10),
                new Point(LeftPadding, stripTop + 1));
            return;
        }

        double scale = ActualWidth / _document.Length;
        foreach (HexHighlight region in StructureHighlights)
        {
            var brush = new SolidColorBrush(Color.FromArgb(0xD0, region.Color.R, region.Color.G, region.Color.B));
            brush.Freeze();

            double x = region.Offset * scale;
            double width = Math.Max(1.5, region.Length * scale);
            dc.DrawRectangle(brush, null, new Rect(x, stripTop + 2.5, width, StructureStripHeight - 5));
        }
    }

    protected override void OnRenderSizeChanged(SizeChangedInfo info)
    {
        base.OnRenderSizeChanged(info);
        ScrollInfoChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// 双屏且两屏缩放不同时，窗口被拖到另一块屏幕会触发 DPI 变化。
    /// 字符宽度与行高是按 DPI 算出来的，必须作废重算，否则光标和选区会整体错位。
    /// </summary>
    protected override void OnDpiChanged(DpiScale oldDpi, DpiScale newDpi)
    {
        base.OnDpiChanged(oldDpi, newDpi);
        _metricsReady = false;
        InvalidateVisual();
        ScrollInfoChanged?.Invoke(this, EventArgs.Empty);
    }

    // ── 绘制 ───────────────────────────────────────────────────────────────

    private void DrawPlaceholder(DrawingContext dc)
    {
        FormattedText text = MakeText("把文件拖到这里，或点击左侧「打开文件」", TryFindBrush("InkFaintBrush", Colors.Gray), 13);
        dc.DrawText(text, new Point(LeftPadding, 60));
    }

    private void DrawEntropyStrip(DrawingContext dc)
    {
        double width = ActualWidth;
        if (width <= 0) return;

        Brush low = TryFindBrush("EntropyLowBrush", Color.FromRgb(0xE8, 0xE1, 0xD3));
        Brush mid = TryFindBrush("EntropyMidBrush", Color.FromRgb(0x8F, 0xB8, 0x9B));
        Brush high = TryFindBrush("EntropyHighBrush", Color.FromRgb(0x2D, 0x5A, 0x3D));

        dc.DrawRectangle(low, null, new Rect(0, 0, width, EntropyStripHeight));

        if (_document is null || _document.Length == 0 || EntropyBlocks.Count == 0) return;

        double scale = width / _document.Length;
        foreach (EntropyBlock block in EntropyBlocks)
        {
            Brush brush = block.Entropy switch
            {
                >= 7.2 => high,
                >= 4.5 => mid,
                _ => low,
            };

            double x = block.Offset * scale;
            double w = Math.Max(0.5, block.Length * scale);
            dc.DrawRectangle(brush, null, new Rect(x, 0, w, EntropyStripHeight));
        }

        // 高亮的区间在色带上也标一下
        foreach (HexHighlight highlight in Highlights)
        {
            double x = highlight.Offset * scale;
            double w = Math.Max(1, highlight.Length * scale);
            var pen = new Pen(new SolidColorBrush(Color.FromArgb(0xCC, highlight.Color.R, highlight.Color.G, highlight.Color.B)), 1);
            dc.DrawRectangle(null, pen, new Rect(x, 0.5, w, EntropyStripHeight - 1));
        }
    }

    private void DrawHeaderRow(DrawingContext dc)
    {
        double y = EntropyStripHeight;
        var background = TryFindBrush("PaperWarmBrush", Color.FromRgb(0xF0, 0xEB, 0xE0));
        dc.DrawRectangle(background, null, new Rect(0, y, ActualWidth, HeaderHeight));

        Brush ink = TryFindBrush("InkFaintBrush", Colors.Gray);
        var sb = new StringBuilder();
        for (int i = 0; i < BytesPerLine; i++) sb.Append(i.ToString("X2")).Append(' ');

        double offsetX = LeftPadding;
        double hexX = offsetX + 8 * _charWidth + ColumnGap;
        double asciiX = hexX + (BytesPerLine * 3) * _charWidth + ColumnGap;

        dc.DrawText(MakeText("偏移", ink, 11), new Point(offsetX, y + 4));
        dc.DrawText(MakeText(sb.ToString(), ink, 11), new Point(hexX, y + 4));
        dc.DrawText(MakeText("ASCII", ink, 11), new Point(asciiX, y + 4));

        var pen = new Pen(TryFindBrush("BorderSubtleBrush", Colors.LightGray), 1);
        dc.DrawLine(pen, new Point(0, y + HeaderHeight - 0.5), new Point(ActualWidth, y + HeaderHeight - 0.5));
    }

    private void DrawByteRows(DrawingContext dc)
    {
        ByteDocument document = _document!;
        ReadOnlySpan<byte> data = document.Span;

        Brush ink = TryFindBrush("HexTextBrush", Colors.DimGray);
        Brush offsetBrush = TryFindBrush("HexOffsetBrush", Colors.Gray);
        Brush asciiBrush = TryFindBrush("HexAsciiBrush", Colors.Gray);
        Brush selectionBrush = TryFindBrush("SelectionBrush", Color.FromRgb(0xD4, 0xE8, 0xDA));
        Brush caretBrush = TryFindBrush("BambooBrush", Colors.Green);
        Brush highlightBrush = TryFindBrush("BambooGlowBrush", Color.FromRgb(0xD4, 0xE8, 0xDA));
        Brush hitBrush = TryFindBrush("BambooMistBrush", Color.FromRgb(0xE8, 0xF0, 0xEB));

        int firstLine = FirstVisibleLine;
        int lines = VisibleLineCount;
        int start = firstLine * BytesPerLine;
        double baseY = EntropyStripHeight + HeaderHeight;

        double offsetX = LeftPadding;
        double hexX = offsetX + 8 * _charWidth + ColumnGap;
        double asciiX = hexX + (BytesPerLine * 3) * _charWidth + ColumnGap;

        // 选区
        int selStart = SelectionStart;
        int selEnd = selStart + SelectionLength;

        var searchLookup = BuildSearchLookup(firstLine, lines);

        var hex = new StringBuilder(BytesPerLine * 3);
        var ascii = new StringBuilder(BytesPerLine);

        for (int i = 0; i < lines; i++)
        {
            int line = firstLine + i;
            int lineStart = line * BytesPerLine;
            if (lineStart >= document.Length) break;

            int lineLength = Math.Min(BytesPerLine, document.Length - lineStart);
            double rowY = baseY + i * _lineHeight;

            // 搜索命中仍用底色标出（那是"查找结果"，与结构/线索的标记性质不同）
            for (int b = 0; b < lineLength; b++)
            {
                int offset = lineStart + b;
                if (searchLookup.Contains(offset))
                {
                    dc.DrawRectangle(hitBrush, null, new Rect(hexX + b * 3 * _charWidth - 2, rowY - 1, 3 * _charWidth, _lineHeight + 1));
                }
            }

            // 选区背景
            if (selEnd > selStart && selEnd > lineStart && selStart < lineStart + lineLength)
            {
                int from = Math.Max(selStart, lineStart) - lineStart;
                int to = Math.Min(selEnd, lineStart + lineLength) - lineStart;
                dc.DrawRectangle(selectionBrush, null,
                    new Rect(hexX + from * 3 * _charWidth - 2, rowY - 1, (to - from) * 3 * _charWidth, _lineHeight + 1));
                dc.DrawRectangle(selectionBrush, null,
                    new Rect(asciiX + from * _charWidth, rowY - 1, (to - from) * _charWidth, _lineHeight + 1));
            }

            hex.Clear();
            ascii.Clear();
            for (int b = 0; b < lineLength; b++)
            {
                byte value = data[lineStart + b];
                hex.Append(value.ToString("X2")).Append(' ');
                ascii.Append(value is >= 0x20 and < 0x7F ? (char)value : '.');
            }

            string offsetText = lineStart.ToString("X8");
            dc.DrawText(MakeText(offsetText, offsetBrush, 12), new Point(offsetX, rowY));

            // 结构/线索的标记**染字符颜色**，不铺背景色块。
            // 背景块会把字节本身糊掉、深浅不一的色块也很吵；
            // 染色则是"高亮这段字符"，既保留可读性，又能直接看出是哪一段。
            bool lineHasMark = false;
            for (int b = 0; b < lineLength && !lineHasMark; b++)
            {
                lineHasMark = FindMark(lineStart + b) is not null;
            }

            if (!lineHasMark)
            {
                dc.DrawText(MakeText(hex.ToString(), ink, 12), new Point(hexX, rowY));
                dc.DrawText(MakeText(ascii.ToString(), asciiBrush, 12), new Point(asciiX, rowY));
                continue;
            }

            // 只有带标记的行才逐字节绘制，普通行仍整行一次画（性能考虑）
            string asciiText = ascii.ToString();
            for (int b = 0; b < lineLength; b++)
            {
                int offset = lineStart + b;
                Brush hexBrush = ink;
                Brush charBrush = asciiBrush;

                if (FindMark(offset) is { } mark)
                {
                    var markBrush = new SolidColorBrush(mark.Color);
                    markBrush.Freeze();
                    hexBrush = markBrush;
                    charBrush = markBrush;
                }

                dc.DrawText(MakeText(data[offset].ToString("X2"), hexBrush, 12),
                    new Point(hexX + b * 3 * _charWidth, rowY));
                dc.DrawText(MakeText(asciiText[b].ToString(), charBrush, 12),
                    new Point(asciiX + b * _charWidth, rowY));
            }
        }

        DrawCaret(dc, caretBrush, hexX, asciiX, baseY);
    }

    private void DrawCaret(DrawingContext dc, Brush caretBrush, double hexX, double asciiX, double baseY)
    {
        if (!IsKeyboardFocusWithin || _document is null || _document.Length == 0) return;

        int line = CaretOffset / BytesPerLine;
        int column = CaretOffset % BytesPerLine;
        int row = line - FirstVisibleLine;
        if (row < 0 || row >= VisibleLineCount) return;

        double rowY = baseY + row * _lineHeight;

        // 光标停在哪一列，插入符就画在哪一列 —— 否则在 ASCII 列打字时看不到光标在哪
        double x = _caretOnAscii
            ? asciiX + column * _charWidth
            : hexX + (column * 3 + _nibble) * _charWidth;

        dc.DrawRectangle(caretBrush, null, new Rect(x, rowY - 1, 1.6, _lineHeight + 1));
    }

    /// <summary>
    /// 找出该偏移的标记。**需要注意的（红）优先于结构分区（浅色）**。
    ///
    /// 直接线性查而不是预先建 offset→mark 的 map：
    /// 标记统共只有几条，逐字节查的开销可以忽略，
    /// 却能避免"按可见行裁剪范围"那一步出错（实测就栽在那里：
    /// 只有首屏的标记生效，滚动之后的标记全部丢失）。
    /// </summary>
    private HexHighlight? FindMark(int offset)
    {
        foreach (HexHighlight mark in AttentionHighlights)
        {
            if (offset >= mark.Offset && offset < mark.Offset + mark.Length) return mark;
        }

        foreach (HexHighlight highlight in Highlights)
        {
            if (offset >= highlight.Offset && offset < highlight.Offset + highlight.Length) return highlight;
        }

        return null;
    }

    private HashSet<int> BuildSearchLookup(int firstLine, int lineCount)
    {
        var set = new HashSet<int>();
        if (SearchHits.Count == 0) return set;

        int from = firstLine * BytesPerLine;
        int to = from + lineCount * BytesPerLine;

        foreach (SearchHit hit in SearchHits)
        {
            int start = Math.Max(hit.Offset, from);
            int end = Math.Min(hit.Offset + hit.Length, to);
            for (int i = start; i < end; i++) set.Add(i);
        }
        return set;
    }

    // ── 交互 ───────────────────────────────────────────────────────────────

    protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        base.OnMouseLeftButtonDown(e);
        Focus();

        if (_document is null) return;
        if (e.ClickCount == 2) { SelectAllBytes(); return; }

        if (TryGetOffsetFromPoint(e.GetPosition(this), out int offset, out bool onAscii))
        {
            CaretOffset = offset;
            CaretOnAscii = onAscii;      // 走属性：顺带同步输入法开关
            SelectionAnchor = Keyboard.Modifiers.HasFlag(ModifierKeys.Shift) ? SelectionAnchor : offset;
            _nibble = 0;
            InvalidateVisual();
            CaretMoved?.Invoke(this, EventArgs.Empty);
        }
    }

    protected override void OnMouseRightButtonUp(MouseButtonEventArgs e)
    {
        base.OnMouseRightButtonUp(e);

        // 显式打开右键菜单，不依赖 ContextMenuService 的隐式弹出。
        // 自绘控件 + WindowChrome 自定义窗口边框的情况下，隐式弹出实测不生效。
        if (ContextMenu is null) return;

        Focus();
        ContextMenu.PlacementTarget = this;
        ContextMenu.Placement = System.Windows.Controls.Primitives.PlacementMode.MousePoint;
        ContextMenu.IsOpen = true;
        e.Handled = true;
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);

        if (e.LeftButton == MouseButtonState.Pressed && _document is not null)
        {
            if (TryGetOffsetFromPoint(e.GetPosition(this), out int offset))
            {
                CaretOffset = offset;
                InvalidateVisual();
                CaretMoved?.Invoke(this, EventArgs.Empty);
            }
            return;
        }

        // 悬停：显示该位置所属结构区域的名称
        if (TryGetOffsetFromPoint(e.GetPosition(this), out int hoverOffset))
        {
            string? label = FindLabelAt(hoverOffset);
            if (!string.Equals(label, _hoverLabel, StringComparison.Ordinal))
            {
                _hoverLabel = label;
                System.Windows.Controls.ToolTipService.SetToolTip(this, label);
            }
        }
    }

    /// <summary>找出覆盖该偏移的最后一个带标签的高亮（列表顺序即绘制优先级）。</summary>
    private string? FindLabelAt(int offset)
    {
        string? result = null;

        // 优先级：需要注意的 > 结构区域 > 普通标记（与绘制覆盖顺序保持一致）
        foreach (HexHighlight mark in AttentionHighlights)
        {
            if (mark.Label is null) continue;
            if (offset >= mark.Offset && offset < mark.Offset + mark.Length) result = mark.Label;
        }

        foreach (HexHighlight region in StructureHighlights)
        {
            if (region.Label is null) continue;
            if (offset >= region.Offset && offset < region.Offset + region.Length) result = region.Label;
        }

        foreach (HexHighlight highlight in Highlights)
        {
            if (highlight.Label is null) continue;
            if (offset >= highlight.Offset && offset < highlight.Offset + highlight.Length) result = highlight.Label;
        }

        return result;
    }

    protected override void OnMouseWheel(MouseWheelEventArgs e)
    {
        base.OnMouseWheel(e);
        int delta = e.Delta > 0 ? -3 : 3;
        SetFirstVisibleLine(FirstVisibleLine + delta);
        e.Handled = true;
    }

    protected override void OnGotKeyboardFocus(KeyboardFocusChangedEventArgs e)
    {
        base.OnGotKeyboardFocus(e);
        InvalidateVisual();
    }

    protected override void OnLostKeyboardFocus(KeyboardFocusChangedEventArgs e)
    {
        base.OnLostKeyboardFocus(e);
        InvalidateVisual();
    }

    /// <summary>
    /// 光标是否停在 ASCII 列（外部/自检可设置）。
    /// true 时键盘输入按**字符**写入字节，false 时按**半字节**编辑十六进制。
    /// 赋值时会顺带开关输入法 —— 见 setter 里的说明。
    /// </summary>
    public bool CaretOnAscii
    {
        get => _caretOnAscii;
        set
        {
            if (_caretOnAscii == value) return;

            _caretOnAscii = value;

            // ASCII 列**禁用输入法**：否则中文输入法会把拼音字母（它们本身就是 ASCII）
            // 直接敲进文件，形成极难排查的污染。这也是"只接受 ASCII"最根本的一道防线。
            try
            {
                InputMethod.SetIsInputMethodEnabled(this, !value);
            }
            catch
            {
                // 某些宿主环境下设置输入法会抛异常，忽略即可（过滤逻辑仍然兜底）
            }

            InvalidateVisual();
        }
    }

    /// <summary>
    /// **在 ASCII 列直接编辑**：敲一个可打印 ASCII 就把它写进当前字节，并前进一格。
    ///
    /// 用 OnTextInput 而不是 OnKeyDown：它天然处理了 Shift、大小写、输入法与键盘布局；
    /// 自己从 Key 反推字符会漏掉一堆情况。
    ///
    /// **只接受纯 ASCII，其余一律拒绝**（并且 `CaretOnAscii` 会顺手把输入法关掉）：
    /// 中文输入法开着时，拼音字母本身就是 ASCII —— 不拦的话会往文件里塞一串拼音，
    /// 这类污染极难排查。规则是：**宁可什么都不做，也不能写进非 ASCII**。
    /// </summary>
    protected override void OnTextInput(TextCompositionEventArgs e)
    {
        base.OnTextInput(e);

        if (_document is null || !_caretOnAscii) return;
        if (string.IsNullOrEmpty(e.Text)) return;

        // 一次只写一个字节：多字符输入（粘贴、输入法上屏）不属于"敲一个字符"的语义
        if (e.Text.Length != 1)
        {
            e.Handled = true;
            return;
        }

        char ch = e.Text[0];
        if (ch is < (char)0x20 or > (char)0x7E)      // 可打印 ASCII 之外（含中文、emoji 代理对、控制字符）
        {
            e.Handled = true;
            return;
        }

        // **插入**而不是覆盖：在 ASCII 列打字是"往这里塞一个字符"，
        // 覆盖会把后面的内容冲掉（用户明确反馈过这一点）
        InsertByte((byte)ch);
        e.Handled = true;
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        if (_document is null) return;

        bool shift = Keyboard.Modifiers.HasFlag(ModifierKeys.Shift);
        bool control = Keyboard.Modifiers.HasFlag(ModifierKeys.Control);
        int length = _document.Length;

        switch (e.Key)
        {
            case Key.Left:
                MoveCaret(CaretOffset - 1, shift);
                e.Handled = true;
                return;

            case Key.Right:
                MoveCaret(CaretOffset + 1, shift);
                e.Handled = true;
                return;

            case Key.Up:
                MoveCaret(CaretOffset - BytesPerLine, shift);
                e.Handled = true;
                return;

            case Key.Down:
                MoveCaret(CaretOffset + BytesPerLine, shift);
                e.Handled = true;
                return;

            case Key.PageUp:
                MoveCaret(CaretOffset - VisibleLineCount * BytesPerLine, shift);
                e.Handled = true;
                return;

            case Key.PageDown:
                MoveCaret(CaretOffset + VisibleLineCount * BytesPerLine, shift);
                e.Handled = true;
                return;

            case Key.Home:
                MoveCaret(control ? 0 : CaretOffset - CaretOffset % BytesPerLine, shift);
                e.Handled = true;
                return;

            case Key.End:
                MoveCaret(control ? Math.Max(0, length - 1) : CaretOffset - CaretOffset % BytesPerLine + BytesPerLine - 1, shift);
                e.Handled = true;
                return;

            case Key.Delete:
                DeleteSelection();
                e.Handled = true;
                return;

            case Key.Back:
                if (CaretOffset > 0) { MoveCaret(CaretOffset - 1, false); DeleteSelection(); }
                e.Handled = true;
                return;

            case Key.Escape:
                SelectionAnchor = CaretOffset;
                InvalidateVisual();
                e.Handled = true;
                return;
        }

        if (control)
        {
            switch (e.Key)
            {
                case Key.C:
                    // 默认智能复制（内容像文本就给文本），Shift 强制复制十六进制。
                    // 旧版这里硬编码 CopySelectionAsHex()，选中 ASCII 文本粘出来仍是一串 hex。
                    if (Keyboard.Modifiers.HasFlag(ModifierKeys.Shift)) CopySelectionAsHex();
                    else CopySelectionSmart();
                    e.Handled = true;
                    return;

                case Key.V:
                    PasteFromClipboard();
                    e.Handled = true;
                    return;

                case Key.A:
                    SelectAllBytes();
                    e.Handled = true;
                    return;
            }
            return;
        }

        // 半字节编辑：先改高四位，再改低四位，然后前移一个字节
        // 半字节编辑：先改高四位，再改低位。
        //
        // ⚠️ 光标在 ASCII 列时必须**整段跳过**：否则 0-9 / A-F 会被当成半字节吃掉，
        //    字符根本到不了 OnTextInput。用户反馈的"个别按键会吃掉字符"就是这个 ——
        //    偏偏只有这 16 个键会被吃，所以听起来像"个别按键"。
        if (!_caretOnAscii && TryParseHexDigit(e.Key, out int digit))
        {
            ApplyHexDigit(digit);
            e.Handled = true;
        }
    }

    /// <summary>
    /// 输入一个十六进制半字节（0–15）。
    /// 从键盘事件里独立出来，既方便自检复用，也让"先高位、后低位、再前移"的规则只有一处实现。
    /// </summary>
    public void ApplyHexDigit(int digit)
    {
        if (_document is null) return;
        digit &= 0x0F;

        int length = _document.Length;
        byte current = CaretOffset < length ? _document[CaretOffset] : (byte)0;
        byte updated = _nibble == 0
            ? (byte)((digit << 4) | (current & 0x0F))
            : (byte)((current & 0xF0) | digit);

        if (_nibble == 0)
        {
            _document.Overwrite(CaretOffset, [updated]);
            _nibble = 1;
            AfterEdit(keepNibble: true);
        }
        else
        {
            _document.Overwrite(CaretOffset, [updated]);
            _nibble = 0;
            CaretOffset = Math.Min(CaretOffset + 1, Math.Max(0, _document.Length - 1));
            SelectionAnchor = CaretOffset;
            AfterEdit();
        }
    }

    private void SelectAllBytes()
    {
        if (_document is null) return;
        SelectionAnchor = 0;
        CaretOffset = Math.Max(0, _document.Length - 1);
        InvalidateVisual();
        CaretMoved?.Invoke(this, EventArgs.Empty);
    }

    private void MoveCaret(int offset, bool extendSelection)
    {
        if (_document is null) return;
        int clamped = Math.Clamp(offset, 0, Math.Max(0, _document.Length - 1));
        CaretOffset = clamped;
        if (!extendSelection) SelectionAnchor = clamped;
        _nibble = 0;
        EnsureCaretVisible();
        InvalidateVisual();
        CaretMoved?.Invoke(this, EventArgs.Empty);
    }

    private void EnsureCaretVisible()
    {
        int line = CaretOffset / BytesPerLine;
        int visible = VisibleLineCount;

        if (line < FirstVisibleLine) SetFirstVisibleLine(line);
        else if (line >= FirstVisibleLine + visible) SetFirstVisibleLine(line - visible + 1);
    }

    private void AfterEdit(bool keepNibble = false)
    {
        if (!keepNibble) _nibble = 0;
        InvalidateVisual();
        ContentEdited?.Invoke(this, EventArgs.Empty);
        CaretMoved?.Invoke(this, EventArgs.Empty);
    }

    private bool TryGetOffsetFromPoint(Point point, out int offset)
        => TryGetOffsetFromPoint(point, out offset, out _);

    /// <summary>
    /// 多返回一个"是否落在 ASCII 列" —— 决定敲键盘是**直接写字节**还是**改半字节**。
    /// </summary>
    private bool TryGetOffsetFromPoint(Point point, out int offset, out bool onAscii)
    {
        offset = 0;
        onAscii = false;
        if (_document is null) return false;

        EnsureMetrics();
        double relativeY = point.Y - EntropyStripHeight - HeaderHeight;
        if (relativeY < 0) return false;

        int line = FirstVisibleLine + (int)(relativeY / _lineHeight);
        int lineStart = line * BytesPerLine;
        if (lineStart >= _document.Length) return false;

        double offsetX = LeftPadding;
        double hexX = offsetX + 8 * _charWidth + ColumnGap;
        double asciiX = hexX + (BytesPerLine * 3) * _charWidth + ColumnGap;

        int column;
        if (point.X >= asciiX)
        {
            column = (int)((point.X - asciiX) / _charWidth);
            onAscii = true;
        }
        else if (point.X >= hexX)
        {
            column = (int)((point.X - hexX) / (_charWidth * 3));
        }
        else
        {
            column = 0;
        }

        column = Math.Clamp(column, 0, BytesPerLine - 1);
        offset = Math.Clamp(lineStart + column, 0, Math.Max(0, _document.Length - 1));
        return true;
    }

    // ── 剪贴板文本 ─────────────────────────────────────────────────────────

    private (int Start, int Length) SelectionRange()
    {
        if (_document is null) return (0, 0);
        if (SelectionLength > 0) return (SelectionStart, SelectionLength);
        return (CaretOffset, 1);
    }

    private string BuildHexText()
    {
        if (_document is null) return string.Empty;
        (int start, int length) = SelectionRange();
        byte[] data = _document.ReadRange(start, length);

        var sb = new StringBuilder(data.Length * 3);
        for (int i = 0; i < data.Length; i++)
        {
            if (i > 0) sb.Append(' ');
            sb.Append(data[i].ToString("X2"));
        }
        return sb.ToString();
    }

    private string BuildAsciiText()
    {
        if (_document is null) return string.Empty;
        (int start, int length) = SelectionRange();
        byte[] data = _document.ReadRange(start, length);

        var sb = new StringBuilder(data.Length);
        foreach (byte b in data) sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
        return sb.ToString();
    }

    private string BuildCArrayText()
    {
        if (_document is null) return string.Empty;
        (int start, int length) = SelectionRange();
        byte[] data = _document.ReadRange(start, length);

        var sb = new StringBuilder(data.Length * 6);
        for (int i = 0; i < data.Length; i++)
        {
            if (i > 0) sb.Append(i % 16 == 0 ? ",\n" : ", ");
            sb.Append("0x").Append(data[i].ToString("X2"));
        }
        return sb.ToString();
    }

    private string BuildPythonText()
    {
        if (_document is null) return string.Empty;
        (int start, int length) = SelectionRange();
        byte[] data = _document.ReadRange(start, length);

        var sb = new StringBuilder(data.Length * 4 + 4);
        sb.Append("b\"");
        foreach (byte b in data)
        {
            if (b is >= 0x20 and < 0x7F && b != (byte)'"' && b != (byte)'\\') sb.Append((char)b);
            else sb.Append("\\x").Append(b.ToString("x2"));
        }
        sb.Append('"');
        return sb.ToString();
    }

    private static void SetClipboard(string text)
    {
        if (string.IsNullOrEmpty(text)) return;
        try
        {
            Clipboard.SetText(text);
        }
        catch
        {
            // 剪贴板被其他进程占用时忽略（不打断分析流程）
        }
    }

    /// <summary>把剪贴板文本解读为字节：优先按十六进制，否则按 UTF-8 文本。</summary>
    private static byte[] ParseHexOrText(string text)
    {
        string cleaned = new(text.Where(static c => !char.IsWhiteSpace(c)).ToArray());
        cleaned = cleaned.Replace("0x", string.Empty, StringComparison.OrdinalIgnoreCase)
                         .Replace(",", string.Empty)
                         .Replace("\\x", string.Empty, StringComparison.OrdinalIgnoreCase);

        bool looksHex = cleaned.Length >= 2 && cleaned.Length % 2 == 0 && cleaned.All(Uri.IsHexDigit);
        if (looksHex)
        {
            try
            {
                return Convert.FromHexString(cleaned);
            }
            catch (FormatException)
            {
                // 落到文本分支
            }
        }

        return Encoding.UTF8.GetBytes(text);
    }

    private static bool TryParseHexDigit(Key key, out int digit)
    {
        digit = 0;

        if (key is >= Key.D0 and <= Key.D9)
        {
            digit = key - Key.D0;
            return true;
        }
        if (key is >= Key.NumPad0 and <= Key.NumPad9)
        {
            digit = key - Key.NumPad0;
            return true;
        }
        if (key is >= Key.A and <= Key.F)
        {
            digit = 10 + (key - Key.A);
            return true;
        }
        return false;
    }

    // ── 文本与度量 ─────────────────────────────────────────────────────────

    private void EnsureMetrics()
    {
        if (_metricsReady) return;

        _typeface = new Typeface(
            new FontFamily("Cascadia Mono, Consolas, Courier New, monospace"),
            FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);

        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var probe = new FormattedText("0000000000000000", CultureInfo.InvariantCulture,
            FlowDirection.LeftToRight, _typeface, 12, Brushes.Black, dpi);

        _charWidth = probe.Width / 16.0;
        _lineHeight = Math.Round(probe.Height + 4);
        _metricsReady = true;
    }

    private FormattedText MakeText(string text, Brush brush, double size)
    {
        EnsureMetrics();
        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        return new FormattedText(text, CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
            _typeface, size, brush, dpi);
    }

    private Brush TryFindBrush(string key, Color fallback)
    {
        if (TryFindResource(key) is Brush brush) return brush;
        var solid = new SolidColorBrush(fallback);
        solid.Freeze();
        return solid;
    }
}
