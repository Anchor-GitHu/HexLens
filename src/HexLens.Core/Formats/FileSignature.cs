namespace HexLens.Core.Formats;

/// <summary>文件大类（用于界面分组与图标配色）。</summary>
public enum FileCategory
{
    Image,
    Audio,
    Video,
    Archive,
    Document,
    Executable,
    Database,
    Font,
    Crypto,
    Network,
    Disk,
    Other,
}

/// <summary>匹配置信度。</summary>
public enum Confidence
{
    /// <summary>仅有魔数，可能误报（如 "MZ"、"BM"）。</summary>
    Low = 1,

    /// <summary>魔数较独特，或结构部分可校验。</summary>
    Medium = 2,

    /// <summary>魔数独特且结构自洽（或校验和通过）。</summary>
    High = 3,
}

/// <summary>
/// 一个匹配锚点：在 <see cref="RelativeOffset"/> 处应出现 <see cref="Pattern"/>。
/// 掩码中值为 0 的字节表示"任意"，用于 RIFF 家族这类中间带长度字段的签名。
/// </summary>
public sealed record MagicAnchor(byte[] Pattern, int RelativeOffset = 0, byte[]? Mask = null, string? Note = null)
{
    /// <summary>在给定位置尝试匹配锚点。</summary>
    public bool MatchesAt(ReadOnlySpan<byte> data, int position)
    {
        if (position < 0 || position + Pattern.Length > data.Length) return false;
        if (Mask is null)
            return data.Slice(position, Pattern.Length).SequenceEqual(Pattern);

        for (int i = 0; i < Pattern.Length; i++)
        {
            if (Mask[i] == 0) continue;
            if (data[position + i] != Pattern[i]) return false;
        }
        return true;
    }
}

/// <summary>长度推导策略：知道起点后如何确定这个内嵌文件到哪里结束。</summary>
public enum SizeStrategy
{
    /// <summary>无法推导，只能给估算（到下一个签名或文件末尾）。</summary>
    Unknown,

    /// <summary>到文件末尾（尾部附加型载荷）。</summary>
    ToEndOfFile,

    /// <summary>PNG：到 IEND 块结束（含 4 字节 CRC）。</summary>
    PngToIend,

    /// <summary>JPEG：到 EOI（FF D9）。</summary>
    JpegToEoi,

    /// <summary>GIF：到 trailer（0x3B）。</summary>
    GifToTrailer,

    /// <summary>ZIP：到 EOCD（含注释）。</summary>
    ZipToEocd,

    /// <summary>PDF：到 %%EOF。</summary>
    PdfToEof,

    /// <summary>RIFF（WAV/AVI/WEBP）：8 字节头 + size 字段。</summary>
    RiffSize,

    /// <summary>BMP：头部 size 字段。</summary>
    BmpSize,

    /// <summary>GZIP：按 deflate 流结束 + ISIZE。</summary>
    GzipStream,

    /// <summary>XZ：按块索引结束标记。</summary>
    XzStream,

    /// <summary>7z：按 next header offset/size 推导。</summary>
    SevenZipStream,

    /// <summary>RAR：遍历块头。</summary>
    RarStream,

    /// <summary>TAR：512 字节块到两个全零块。</summary>
    TarBlocks,

    /// <summary>Matroska/EBML：按元素长度递归。</summary>
    EbmlSize,

    /// <summary>SQLite：页大小 × 页数。</summary>
    SqlitePages,

    /// <summary>PCAP：按包记录遍历。</summary>
    PcapStream,

    /// <summary>Zstandard：帧头 + 块头。</summary>
    ZstdStream,

    /// <summary>固定长度（签名本身即全部内容）。</summary>
    Fixed,
}

/// <summary>
/// 结构校验委托：某些魔数（MZ、BM、CAFEBABE）需要额外校验才能确定文件类型。
/// 用自定义委托而不是 <see cref="Func{T,TResult}"/>，因为 <see cref="ReadOnlySpan{T}"/> 不能作泛型参数。
/// </summary>
/// <param name="data">整个缓冲区。</param>
/// <param name="start">候选文件起点。</param>
public delegate bool SignatureValidator(ReadOnlySpan<byte> data, int start);

/// <summary>
/// 一个文件格式的识别定义。
/// </summary>
public sealed record FileSignature(
    string Id,
    string Name,
    FileCategory Category,
    string[] Extensions,
    IReadOnlyList<MagicAnchor> Anchors,
    SizeStrategy Sizer,
    string Description,
    Confidence BaseConfidence = Confidence.High,
    string? MimeType = null,
    SignatureValidator? Validate = null)
{
    /// <summary>扩展名显示文本，如 ".png"。</summary>
    public string ExtensionText => Extensions.Length == 0 ? string.Empty : "." + string.Join(" / .", Extensions);

    public override string ToString() => $"{Name} ({Id})";
}

/// <summary>一次签名命中。</summary>
public sealed record SignatureMatch(
    FileSignature Signature,
    int Offset,
    int AnchorIndex,
    string? AnchorNote,
    Confidence Confidence);
