using HexLens.Core.Analysis;
using HexLens.Core.Carving;
using HexLens.Core.Clues;
using HexLens.Core.Formats;
using HexLens.Core.Stego;

namespace HexLens.App.ViewModels;

/// <summary>线索列表项（左栏卡片）。</summary>
public sealed class ClueItem(Clue source)
{
    public Clue Source { get; } = source;

    public string Title => Source.Title;

    public string Detail => Source.Detail;

    public string KindText => Source.KindText;

    public string OffsetText => Source.OffsetText;

    public string SizeText => Source.SizeText;

    public string MetaText => $"{Source.OffsetText} · {Source.SizeText} · {ConfidenceText}";

    public string ConfidenceText => Source.Confidence switch
    {
        Confidence.High => "高置信度",
        Confidence.Medium => "中等",
        _ => "参考",
    };

    public double ConfidenceOpacity => Source.Confidence switch
    {
        Confidence.High => 1.0,
        Confidence.Medium => 0.7,
        _ => 0.45,
    };

    public IReadOnlyList<ClueAction> Actions => Source.Actions;

    /// <summary>动作按钮的可用性（当前只有导出与跳转可直接执行）。</summary>
    public bool HasExtractAction => Source.Actions.Any(static a => a.Kind == ClueActionKind.ExtractRange);

    /// <summary>
    /// 线索里携带的「写入修复」动作（如把文件头改成正确的签名），没有则为 null。
    /// 这类动作会**真正改文档**，所以界面上要给一个明确的按钮，而不是藏在右键菜单里。
    /// </summary>
    public ClueAction? FixAction
        => Source.Actions.FirstOrDefault(static a => a.Kind == ClueActionKind.WritePayload);

    /// <summary>是否存在可一键应用的修复。</summary>
    public bool HasFixAction => FixAction is not null;
}

/// <summary>
/// XOR 暴力破解的一个候选。
///
/// 带上 <see cref="Offset"/> / <see cref="Length"/> 是必要的：界面上列出候选时
/// 用户可能已经改了选区，如果"应用 key"时再读一次当前选区，就会作用到错的区间上。
/// </summary>
public sealed class XorCandidateItem(XorCandidate source, int offset, int length)
{
    public XorCandidate Source { get; } = source;

    /// <summary>破解时使用的区间起点。</summary>
    public int Offset { get; } = offset;

    /// <summary>破解时使用的区间长度。</summary>
    public int Length { get; } = length;

    /// <summary>密钥字节。</summary>
    public byte[] Key => Source.Key;

    public string KeyText => Source.KeyText;

    /// <summary>解密结果预览。</summary>
    public string Preview => Source.Preview;

    /// <summary>给这个分的依据。</summary>
    public string Reason => Source.Reason;
}

/// <summary>发现的文件列表项。</summary>
public sealed class CarvedFileItem(CarvedFile source){
    public CarvedFile Source { get; } = source;

    public string Name => Source.Signature.Name;

    public string ExtensionText => Source.Signature.ExtensionText;

    public string RangeText => $"{Source.RangeText}  ({Source.SizeText})";

    public string Note => Source.Note;

    public string PositionText => Source.IsEmbedded
        ? (Source.IsNested ? "位于其他文件内部" : "位于主文件之外（可疑）")
        : "主文件";

    public bool IsSuspicious => Source.IsEmbedded && !Source.IsNested;

    public string CategoryText => Source.Signature.Category switch
    {
        FileCategory.Image => "图像",
        FileCategory.Audio => "音频",
        FileCategory.Video => "视频",
        FileCategory.Archive => "归档",
        FileCategory.Document => "文档",
        FileCategory.Executable => "可执行",
        FileCategory.Database => "数据库",
        FileCategory.Font => "字体",
        FileCategory.Crypto => "密钥",
        FileCategory.Network => "网络",
        FileCategory.Disk => "磁盘",
        _ => "其他",
    };
}

/// <summary>结构树节点。</summary>
public sealed class StructureItem
{
    public StructureItem(StructureNode node)
    {
        Node = node;
        Children = node.Children?.Select(static c => new StructureItem(c)).ToList() ?? [];
    }

    public StructureNode Node { get; }

    public string Name => Node.Name;

    public string OffsetText => Node.OffsetText;

    public string LengthText => Node.LengthText;

    public string? Detail => Node.Detail;

    public List<StructureItem> Children { get; }

    public string Summary => Detail is null ? $"{OffsetText}  {LengthText}" : $"{OffsetText}  {LengthText}  {Detail}";
}

/// <summary>位平面命中项。</summary>
public sealed class LsbHitItem(LsbHit source)
{
    public LsbHit Source { get; } = source;

    /// <summary>是不是明文载荷（而非可识别文件）。</summary>
    public bool IsText
    {
        get => Source.Kind == Core.Stego.LsbPayloadKind.Text;
    }

    public string Title
    {
        get => IsText
            ? $"位平面里藏有明文（{Source.Confidence}）"
            : $"还原出 {Source.Signature?.Name ?? "文件"}（{Source.Confidence}）";
    }

    /// <summary>明文预览（文件载荷时为空，界面据此决定是否显示这一行）。</summary>
    public string TextPreview
    {
        get => Source.TextPreview ?? string.Empty;
    }

    /// <summary>是否有明文预览可显示。</summary>
    public bool HasTextPreview
    {
        get => !string.IsNullOrEmpty(Source.TextPreview);
    }

    public string ParameterText
    {
        get => Source.Options.Describe(4);
    }

    public string Description
    {
        get => Source.Description;
    }

    public string PayloadSizeText
    {
        get => Source.Payload.Length < 1024
            ? $"{Source.Payload.Length} B"
            : $"{Source.Payload.Length / 1024.0:F1} KiB";
    }
}

/// <summary>字符串列表项。</summary>
public sealed class StringItem(Core.Analysis.ExtractedString source)
{
    public Core.Analysis.ExtractedString Source { get; } = source;

    public string OffsetText => $"0x{Source.Offset:X8}";

    public string KindText => Source.Kind switch
    {
        Core.Analysis.StringKind.Ascii => "ASCII",
        Core.Analysis.StringKind.Utf16Le => "UTF-16LE",
        _ => "UTF-16BE",
    };

    public string Text => Source.Text;

    public string LengthText => $"{Source.ByteLength} B";
}

/// <summary>直方图柱。</summary>
public sealed class HistogramBar(int index, long count, double ratio)
{
    public int Index { get; } = index;

    public long Count { get; } = count;

    /// <summary>柱高比例（0..1）。</summary>
    public double Ratio { get; } = ratio;

    /// <summary>像素高度（画布 96px 高）。</summary>
    public double BarHeight => Math.Max(1, Ratio * 96);

    public string Tooltip => $"0x{Index:X2}：{Count} 次";

    public string ByteText => Index.ToString("X2");
}

/// <summary>高熵区列表项。</summary>
public sealed class EntropyRegionItem(Core.Analysis.EntropyBlock block)
{
    public Core.Analysis.EntropyBlock Block { get; } = block;

    public string RangeText => $"0x{Block.Offset:X} · {Block.Length:N0} 字节";

    public string EntropyText => $"熵 {Block.Entropy:F2}";
}

/// <summary>数据检视条目（类型名 + 解释出的值）。</summary>
public sealed class InspectorEntry(string name, string value)
{
    public string Name { get; } = name;

    public string Value { get; } = value;
}

/// <summary>编码识别建议项。</summary>
public sealed class MagicItem(Interop.MagicSuggestion source)
{
    public Interop.MagicSuggestion Source { get; } = source;

    public string Algorithm => Source.Algorithm;

    public string Reason => Source.Reason;

    public string Preview => Source.Preview;

    public string ScoreText => Source.ScoreText;

    /// <summary>置信度条宽度（固定 120 px 基准，避免为一个进度条引入转换器）。</summary>
    public double ScoreBarWidth => Math.Max(2, Source.ScoreRatio * 120);
}
