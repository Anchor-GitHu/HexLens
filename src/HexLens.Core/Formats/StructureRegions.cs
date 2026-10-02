using HexLens.Core.Carving;

namespace HexLens.Core.Formats;

/// <summary>
/// 结构区域类别 —— 决定十六进制视图里的着装配色，也是结构页图例的内容。
/// </summary>
public enum StructureCategory
{
    /// <summary>无法归类（不参与着色）。</summary>
    Unknown,

    /// <summary>文件签名与容器头（PNG 签名、DOS 头、RIFF 头、ftyp…）。</summary>
    FileHeader,

    /// <summary>格式自身的头部描述（IHDR、BITMAPINFOHEADER、PE 签名+COFF…）。</summary>
    FormatHeader,

    /// <summary>元数据 / 注释 / 文本块（tEXt、COM、LIST INFO…）。</summary>
    Metadata,

    /// <summary>调色板（PLTE）。</summary>
    Palette,

    /// <summary>表与索引（节表、中央目录、DQT/DHT、SeekHead、Cues…）。</summary>
    Table,

    /// <summary>可执行代码（.text 等节）。</summary>
    Code,

    /// <summary>资源（.rsrc 等）。</summary>
    Resource,

    /// <summary>内容数据（IDAT、data、mdat、帧数据、条目数据…）。</summary>
    Content,

    /// <summary>结束标记（IEND、EOI、%%EOF、Trailer…）。</summary>
    Footer,

    /// <summary>文件声明范围之外的附加数据（覆盖层、尾部载荷）。</summary>
    Overlay,

    /// <summary>填充与对齐（padding、free…）。</summary>
    Padding,
}

/// <summary>一个可用于着色的结构区域（扁平化后的区间）。</summary>
/// <param name="Offset">起点。</param>
/// <param name="Length">长度。</param>
/// <param name="Name">显示名（沿结构树节点名）。</param>
/// <param name="Category">类别。</param>
public sealed record StructureRegion(int Offset, int Length, string Name, StructureCategory Category)
{
    /// <summary>结束偏移。</summary>
    public int End => Offset + Length;
}

/// <summary>
/// 结构分类器：按结构树节点名推断类别。
///
/// 为什么用"名字推断"而不是给每个解析器加类别字段：
/// 解析器已经有 10 多个格式、上百个节点名，逐个改要动所有解析代码且容易漏；
/// 而节点名本身就是稳定的（IHDR/EOCD/mdat… 都是格式规范里的固定标识）。
/// 规则按"具体 → 宽泛"排序，避免"节头表"被当成"头"这类误判。
/// </summary>
public static class StructureClassifier
{
    /// <summary>推断类别。</summary>
    public static StructureCategory Classify(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return StructureCategory.Unknown;
        string n = name.ToLowerInvariant();

        // ── 结束标记（必须先判：它们常含"结束/尾"等字样）──
        if (n.Contains("iend") || n.Contains("eoi") || n.Contains("trailer")
            || n.Contains("%%eof") || n.Contains("流尾") || n.Contains("stream footer")
            || n.Contains("结束块") || n.Contains("结束标记") || n.Contains("eocd"))
        {
            return StructureCategory.Footer;
        }

        // ── 具体节点名优先 ──
        if (n.Contains("ihdr")) return StructureCategory.FormatHeader;
        if (n.Contains("plte")) return StructureCategory.Palette;
        if (n.Contains("idat")) return StructureCategory.Content;
        if (n.Contains("fdat")) return StructureCategory.Content;
        if (n.Contains("actl") || n.Contains("fctl")) return StructureCategory.Table;
        if (n.StartsWith("tex") || n.Contains("ztxt") || n.Contains("itxt") || n.Contains("exif")) return StructureCategory.Metadata;
        if (n.Contains("gama") || n.Contains("chrm") || n.Contains("srgb") || n.Contains("bkgd")
            || n.Contains("phys") || n.Contains("sbit") || n.Contains("time")) return StructureCategory.Metadata;

        if (n.Contains("bitmapfileheader")) return StructureCategory.FileHeader;
        if (n.Contains("bitmapinfoheader")) return StructureCategory.FormatHeader;

        if (n.StartsWith("app") || n.Contains("jfif")) return StructureCategory.Metadata;
        if (n.Contains("com 注释") || n.Contains("注释")) return StructureCategory.Metadata;
        if (n.Contains("dqt") || n.Contains("dht")) return StructureCategory.Table;
        if (n.Contains("sof")) return StructureCategory.FormatHeader;
        if (n.Contains("sos")) return StructureCategory.Content;

        if (n.Contains("logical screen descriptor")) return StructureCategory.FormatHeader;
        if (n.Contains("图形控制") || n.Contains("应用扩展")) return StructureCategory.Metadata;

        if (n.Contains("riff 头")) return StructureCategory.FileHeader;
        if (n.Contains("fmt ")) return StructureCategory.FormatHeader;
        if (n == "data") return StructureCategory.Content;
        if (n.Contains("list")) return StructureCategory.Metadata;

        if (n.Contains("中央目录") || n.Contains("本地头")) return StructureCategory.Table;
        if (n.StartsWith("条目")) return StructureCategory.Content;
        if (n.Contains("节头表") || n.Contains("节表") || n.Contains("section")) return StructureCategory.Table;

        if (n.Contains("sqlite 头")) return StructureCategory.FormatHeader;
        if (n.Contains("pcap")) return StructureCategory.FormatHeader;
        if (n.Contains("7z 签名") || n.Contains("rar") || n.Contains("签名头")) return StructureCategory.FileHeader;
        if (n.Contains("gzip 成员")) return StructureCategory.Content;
        if (n.Contains("xz 流头")) return StructureCategory.FileHeader;
        if (n.Contains("zstd 帧头")) return StructureCategory.FormatHeader;

        if (n.Contains("seekhead") || n.Contains("cues") || n.Contains("tracks")) return StructureCategory.Table;
        if (n.Contains("cluster")) return StructureCategory.Content;
        if (n.Contains("segment") || n.Contains("ebml 头")) return StructureCategory.FormatHeader;

        if (n.Contains("dos 头")) return StructureCategory.FileHeader;
        if (n.Contains("pe 签名") || n.Contains("coff")) return StructureCategory.FormatHeader;
        if (n.Contains("elf") && n.Contains("头")) return StructureCategory.FormatHeader;

        if (n.Contains("moov")) return StructureCategory.Table;
        if (n.Contains("mdat")) return StructureCategory.Content;
        if (n.Contains("free")) return StructureCategory.Padding;
        if (n.Contains("uuid")) return StructureCategory.Metadata;
        if (n.Contains("ftyp")) return StructureCategory.FileHeader;

        if (n.Contains("附加数据") || n.Contains("覆盖层")) return StructureCategory.Overlay;

        // ── 按节名判断（PE/ELF 的 .text / .rsrc 等）──
        if (n.Contains(".text") || n.Contains(".code") || n.Contains(".plt") || n.Contains(".init")) return StructureCategory.Code;
        if (n.Contains(".rsrc") || n.Contains(".resource")) return StructureCategory.Resource;
        if (n.Contains(".data") || n.Contains(".rdata") || n.Contains(".bss") || n.Contains(".rodata")) return StructureCategory.Content;
        if (n.Contains(".reloc") || n.Contains(".idata") || n.Contains(".edata") || n.Contains(".debug")) return StructureCategory.Table;

        // ── 宽泛兜底（放最后，避免误判上面的具体名）──
        if (n.Contains("魔数") || n.Contains("magic") || n.Contains("header") && !n.Contains("节")) return StructureCategory.FileHeader;
        if (n.Contains("版本") || n.Contains("常量池")) return StructureCategory.FormatHeader;
        if (n.Contains("头")) return StructureCategory.FormatHeader;
        if (n.Contains("表")) return StructureCategory.Table;

        return StructureCategory.Unknown;
    }
}

/// <summary>
/// 把 carving 结果里的结构树展平成扁平区域列表，供十六进制视图着色。
/// </summary>
public static class StructureRegionBuilder
{
    /// <summary>
    /// 构建区域列表（按偏移排序；重叠时保留"更具体"的那一条）。
    /// </summary>
    /// <param name="report">carving 报告。</param>
    /// <param name="dataLength">缓冲区长度（用于补尾部未覆盖区间）。</param>
    public static List<StructureRegion> Build(CarveReport report, int dataLength)
    {
        var regions = new List<StructureRegion>();

        foreach (CarvedFile file in report.Files)
        {
            if (file.Structure is null) continue;
            foreach (StructureNode node in file.Structure) AddNode(regions, node);
        }

        // 按偏移升序；同起点时长者优先（父节点通常更长，但更具体的子节点名更值得保留）
        regions.Sort(static (a, b) =>
        {
            int c = a.Offset.CompareTo(b.Offset);
            return c != 0 ? c : b.Length.CompareTo(a.Length);
        });

        // 去重：同一区间重复出现时只留一条
        var unique = new List<StructureRegion>(regions.Count);
        foreach (StructureRegion region in regions)
        {
            if (region.Length <= 0) continue;
            bool duplicated = unique.Any(u => u.Offset == region.Offset && u.Length == region.Length && u.Category == region.Category);
            if (!duplicated) unique.Add(region);
        }

        return unique;
    }

    private static void AddNode(List<StructureRegion> regions, StructureNode node)
    {
        if (node.Length > 0)
        {
            regions.Add(new StructureRegion(node.Offset, node.Length, node.Name, StructureClassifier.Classify(node.Name)));
        }

        if (node.Children is null) return;
        foreach (StructureNode child in node.Children) AddNode(regions, child);
    }
}
