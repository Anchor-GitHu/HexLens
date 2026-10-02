using HexLens.Core.Formats;

namespace HexLens.Core.Clues;

/// <summary>线索类别。</summary>
public enum ClueKind
{
    /// <summary>主文件声明范围之外还有数据。</summary>
    TrailingData,

    /// <summary>发现内嵌的完整文件。</summary>
    EmbeddedFile,

    /// <summary>位平面里还原出文件。</summary>
    LsbPayload,

    /// <summary>文本里有可疑关键词（flag/secret…）。</summary>
    SuspiciousText,

    /// <summary>疑似 Base64 编码的数据块。</summary>
    Base64Blob,

    /// <summary>归档含加密条目。</summary>
    EncryptedArchive,

    /// <summary>高熵区间（压缩/加密数据）。</summary>
    HighEntropyRegion,

    /// <summary>扩展名与真实类型不符。</summary>
    TypeMismatch,

    /// <summary>动图多帧（可逐帧藏数据）。</summary>
    MultiFrame,

    /// <summary>数据疑似被位反转/字节反转。</summary>
    ReversedData,

    /// <summary>结构异常（CRC 不符、块链中断等）。</summary>
    StructureAnomaly,

    /// <summary>疑似加密载荷：无文件头、高熵、长度规整的数据块。</summary>
    SuspectedCipher,
}

/// <summary>线索可以触发的动作。</summary>
public enum ClueActionKind
{
    /// <summary>把区间导出为文件。</summary>
    ExtractRange,

    /// <summary>在十六进制视图里跳转并选中。</summary>
    RevealInHex,

    /// <summary>对该载体跑位平面分析。</summary>
    AnalyzeLsb,

    /// <summary>查看结构树。</summary>
    ShowStructure,

    /// <summary>把该区段当 Base64 解码并另存。</summary>
    DecodeBase64,

    /// <summary>把整个缓冲区另存为文件。</summary>
    SaveWholeBuffer,

    /// <summary>把 <see cref="ClueAction.Payload"/> 写进 <see cref="ClueAction.Offset"/> 处（如修复文件头）。</summary>
    WritePayload,
}

/// <summary>线索上的一个可执行动作。</summary>
/// <param name="Label">按钮文字。</param>
/// <param name="Kind">动作类型。</param>
/// <param name="Offset">目标区间起点。</param>
/// <param name="Length">目标区间长度。</param>
/// <param name="Hint">附加提示（如建议的文件名）。</param>
/// <param name="Payload">
/// 动作要写入的字节（仅 <see cref="ClueActionKind.WritePayload"/> 用）。
/// 例如"把文件头改成正确的 PNG 签名"时，这里放那 8 个字节。
/// </param>
public sealed record ClueAction(
    string Label,
    ClueActionKind Kind,
    int Offset,
    int Length,
    string? Hint = null,
    byte[]? Payload = null);

/// <summary>
/// 一条线索：标题 + 依据 + 置信度 + 可执行动作。
/// 这是"自动识别"最后一步——把字节事实翻译成能直接上手的结论。
/// </summary>
public sealed record Clue(
    ClueKind Kind,
    string Title,
    string Detail,
    Confidence Confidence,
    int Offset,
    int Length,
    double Priority,
    IReadOnlyList<ClueAction> Actions)
{
    /// <summary>偏移显示。</summary>
    public string OffsetText => $"0x{Offset:X}";

    /// <summary>大小显示。</summary>
    public string SizeText => Length switch
    {
        <= 0 => "—",
        < 1024 => $"{Length} B",
        < 1024 * 1024 => $"{Length / 1024.0:F1} KiB",
        _ => $"{Length / 1048576.0:F2} MiB",
    };

    /// <summary>类别显示名。</summary>
    public string KindText => Kind switch
    {
        ClueKind.TrailingData => "尾部附加",
        ClueKind.EmbeddedFile => "内嵌文件",
        ClueKind.LsbPayload => "位平面",
        ClueKind.SuspiciousText => "可疑文本",
        ClueKind.Base64Blob => "Base64",
        ClueKind.EncryptedArchive => "加密归档",
        ClueKind.HighEntropyRegion => "高熵区",
        ClueKind.TypeMismatch => "类型不符",
        ClueKind.MultiFrame => "多帧",
        ClueKind.ReversedData => "疑似反转",
        ClueKind.StructureAnomaly => "结构异常",
        ClueKind.SuspectedCipher => "疑似加密",
        _ => Kind.ToString(),
    };
}

/// <summary>线索引擎参数。</summary>
public sealed class ClueEngineOptions
{
    /// <summary>是否尝试位反转/字节反转探测。</summary>
    public bool EnableReversalProbe { get; init; } = true;

    /// <summary>反转探测允许的最大文件大小（超过则跳过，避免卡顿）。</summary>
    public int ReversalProbeLimit { get; init; } = 32 * 1024 * 1024;

    /// <summary>Base64 探测的最短长度。</summary>
    public int MinBase64Length { get; init; } = 64;

    /// <summary>最多返回多少条线索。</summary>
    public int MaxClues { get; init; } = 64;
}
