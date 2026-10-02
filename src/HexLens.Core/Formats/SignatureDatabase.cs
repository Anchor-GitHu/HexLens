using System.IO.Compression;

namespace HexLens.Core.Formats;

/// <summary>
/// 文件签名库与扫描引擎：一次遍历即可在任意字节流中找出所有已知文件头。
/// 这是"自动把藏在图片/音频里的文件揪出来"的第一步——签名定位，随后交给长度推导器算区间。
/// </summary>
public static class SignatureDatabase
{
    /// <summary>全部已知签名。</summary>
    public static IReadOnlyList<FileSignature> All { get; } = Build();

    /// <summary>按首字节分桶的锚点索引（单遍扫描的基础）。</summary>
    private static readonly Dictionary<byte, List<(FileSignature Sig, MagicAnchor Anchor, int Index)>> Buckets = BuildBuckets();

    /// <summary>ID 到签名的映射。</summary>
    private static readonly Dictionary<string, FileSignature> ById =
        All.ToDictionary(s => s.Id, StringComparer.OrdinalIgnoreCase);

    /// <summary>按 ID 取签名。</summary>
    public static FileSignature? Get(string id) => ById.GetValueOrDefault(id);

    /// <summary>扩展名（不含点、小写）到签名的映射。同一扩展名可能对应多个格式，取第一个。</summary>
    private static readonly Dictionary<string, FileSignature> ByExtension = BuildExtensionIndex();

    private static Dictionary<string, FileSignature> BuildExtensionIndex()
    {
        var map = new Dictionary<string, FileSignature>(StringComparer.OrdinalIgnoreCase);
        foreach (FileSignature sig in All)
        {
            foreach (string ext in sig.Extensions)
            {
                // 先到先得：先注册的格式优先（签名库里粗粒度格式排在后面对应更具体的）
                if (!map.ContainsKey(ext)) map[ext] = sig;
            }
        }
        return map;
    }

    /// <summary>
    /// 按扩展名查"这个后缀**通常**是什么格式"。
    ///
    /// 用途：文件头被改坏、识别不出任何格式时，靠扩展名反推出**本该**是什么，
    /// 从而给出「把文件头改回来」的建议。注意这只是猜测，调用方应标注为中等置信度。
    /// </summary>
    public static FileSignature? GetByExtension(string extension)
    {
        if (string.IsNullOrEmpty(extension)) return null;
        return ByExtension.GetValueOrDefault(extension.TrimStart('.'));
    }

    /// <summary>
    /// 扫描缓冲区，返回所有签名命中（按偏移升序）。
    /// </summary>
    /// <param name="data">缓冲区。</param>
    /// <param name="start">起始偏移。</param>
    /// <param name="length">扫描长度（null 表示到末尾）。</param>
    /// <param name="maxPerSignature">同一签名的最大命中数，防止噪声型签名刷屏。</param>
    public static List<SignatureMatch> Scan(
        ReadOnlySpan<byte> data,
        int start = 0,
        int? length = null,
        int maxPerSignature = 256)
    {
        var hits = new List<SignatureMatch>();
        if (data.Length == 0) return hits;

        int from = Math.Max(0, start);
        int to = length.HasValue ? Math.Min(data.Length, from + Math.Max(0, length.Value)) : data.Length;
        if (from >= to) return hits;

        var counts = new Dictionary<string, int>(StringComparer.Ordinal);

        for (int i = from; i < to; i++)
        {
            if (!Buckets.TryGetValue(data[i], out var candidates)) continue;

            foreach ((FileSignature sig, MagicAnchor anchor, int index) in candidates)
            {
                if (!anchor.MatchesAt(data, i)) continue;

                int fileStart = i - anchor.RelativeOffset;
                if (fileStart < 0) continue;
                if (sig.Validate is not null && !sig.Validate(data, fileStart)) continue;

                counts.TryGetValue(sig.Id, out int seen);
                if (seen >= maxPerSignature) continue;
                counts[sig.Id] = seen + 1;

                hits.Add(new SignatureMatch(sig, fileStart, index, anchor.Note, sig.BaseConfidence));
            }
        }

        hits.Sort(static (a, b) =>
        {
            int c = a.Offset.CompareTo(b.Offset);
            return c != 0 ? c : b.Confidence.CompareTo(a.Confidence);
        });
        return hits;
    }

    /// <summary>识别缓冲区开头最可能的文件类型（"file" 命令的等价物）。</summary>
    public static SignatureMatch? IdentifyAt(ReadOnlySpan<byte> data, int offset = 0)
    {
        SignatureMatch? best = null;
        foreach (FileSignature sig in All)
        {
            foreach (MagicAnchor anchor in sig.Anchors)
            {
                int pos = offset + anchor.RelativeOffset;
                if (!anchor.MatchesAt(data, pos)) continue;
                if (sig.Validate is not null && !sig.Validate(data, offset)) continue;

                var hit = new SignatureMatch(sig, offset, 0, anchor.Note, sig.BaseConfidence);
                if (best is null || hit.Confidence > best.Confidence) best = hit;
            }
        }
        return best;
    }

    private static Dictionary<byte, List<(FileSignature, MagicAnchor, int)>> BuildBuckets()
    {
        var map = new Dictionary<byte, List<(FileSignature, MagicAnchor, int)>>();
        foreach (FileSignature sig in All)
        {
            for (int i = 0; i < sig.Anchors.Count; i++)
            {
                MagicAnchor anchor = sig.Anchors[i];
                if (anchor.Pattern.Length == 0) continue;
                byte first = anchor.Pattern[0];

                // 首字节必须固定，否则无法用分桶加速（表里所有锚点都满足）
                if (anchor.Mask is not null && anchor.Mask[0] == 0) continue;

                if (!map.TryGetValue(first, out var list))
                {
                    list = [];
                    map[first] = list;
                }
                list.Add((sig, anchor, i));
            }
        }
        return map;
    }

    // ── 表构建辅助 ─────────────────────────────────────────────────────────

    private static byte[] H(string hex)
    {
        string cleaned = hex.Replace(" ", string.Empty).Replace("-", string.Empty);
        try
        {
            return Convert.FromHexString(cleaned);
        }
        catch (FormatException ex)
        {
            // 签名表是手写的十六进制，出错时直接点名是哪一条，否则静态构造异常极难定位
            throw new FormatException($"签名表里的十六进制字面量非法：\"{hex}\"", ex);
        }
    }

    private static MagicAnchor A(string hex, int relativeOffset = 0, string? maskHex = null, string? note = null)
        => new(H(hex), relativeOffset, maskHex is null ? null : H(maskHex), note);

    private static FileSignature S(
        string id,
        string name,
        FileCategory category,
        string[] extensions,
        SizeStrategy sizer,
        string description,
        Confidence confidence = Confidence.High,
        string? mime = null,
        SignatureValidator? validate = null,
        params MagicAnchor[] anchors)
        => new(id, name, category, extensions, anchors, sizer, description, confidence, mime, validate);

    // ── 结构校验器 ─────────────────────────────────────────────────────────

    private static bool IsPe(ReadOnlySpan<byte> d, int s)
    {
        if (s + 0x40 > d.Length) return false;
        int lfanew = BitConverter.ToInt32(d.Slice(s + 0x3C, 4));
        if (lfanew < 0x40 || s + lfanew + 4 > d.Length) return false;
        return d[s + lfanew] == (byte)'P' && d[s + lfanew + 1] == (byte)'E'
            && d[s + lfanew + 2] == 0 && d[s + lfanew + 3] == 0;
    }

    private static bool IsBmp(ReadOnlySpan<byte> d, int s)
    {
        if (s + 18 > d.Length) return false;
        int fileSize = BitConverter.ToInt32(d.Slice(s + 2, 4));
        uint reserved = BitConverter.ToUInt32(d.Slice(s + 6, 4));
        int dataOffset = BitConverter.ToInt32(d.Slice(s + 10, 4));
        // 保留字段必须为 0；尺寸为 0 的变体允许；像素数据偏移要落在合理范围
        if (reserved != 0) return false;
        if (dataOffset < 14 || dataOffset > 1024) return false;
        return fileSize == 0 || fileSize >= 14;
    }

    private static bool IsJavaClass(ReadOnlySpan<byte> d, int s)
    {
        if (s + 8 > d.Length) return false;
        int major = (d[s + 6] << 8) | d[s + 7];
        return major is >= 45 and <= 90;
    }

    private static bool IsMachFat(ReadOnlySpan<byte> d, int s)
    {
        if (s + 8 > d.Length) return false;
        int count = (d[s + 4] << 24) | (d[s + 5] << 16) | (d[s + 6] << 8) | d[s + 7];
        return count is >= 1 and <= 64;
    }

    private static bool IsElf(ReadOnlySpan<byte> d, int s)
    {
        if (s + 6 > d.Length) return false;
        return d[s + 4] is 1 or 2 && d[s + 5] is 1 or 2;
    }

    private static bool IsTtf(ReadOnlySpan<byte> d, int s)
    {
        if (s + 12 > d.Length) return false;
        int numTables = (d[s + 4] << 8) | d[s + 5];
        return numTables is >= 1 and <= 512;
    }

    private static bool IsMp3Frame(ReadOnlySpan<byte> d, int s)
    {
        if (s + 4 > d.Length) return false;
        int b1 = d[s + 1];
        int version = (b1 >> 3) & 3;   // 1 = reserved
        int layer = (b1 >> 1) & 3;     // 0 = reserved
        if (version == 1 || layer == 0) return false;

        int b2 = d[s + 2];
        int bitrate = (b2 >> 4) & 0xF;
        int sampleRate = (b2 >> 2) & 3;
        if (bitrate is 0 or 15) return false;   // 0 = free, 15 = bad
        return sampleRate != 3;
    }

    private static bool IsZlib(ReadOnlySpan<byte> d, int s)
    {
        if (s + 2 > d.Length) return false;
        int cmf = d[s];
        int flg = d[s + 1];
        if ((cmf & 0x0F) != 8) return false;               // deflate
        if (((cmf << 8) | flg) % 31 != 0) return false;    // 头部校验
        if ((flg & 0x20) != 0) return false;               // 不接受预设字典

        try
        {
            // 只探测 4 KiB：zlib 头误报可能以万计，拷贝 1 MiB 会把内存带宽吃光
            using var ms = new MemoryStream(d.Slice(s, Math.Min(d.Length - s, 4096)).ToArray());
            using var z = new ZLibStream(ms, CompressionMode.Decompress);
            Span<byte> probe = stackalloc byte[32];
            return z.Read(probe) > 0;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsIso9660(ReadOnlySpan<byte> d, int s)
    {
        // 主卷描述符位于偏移 32769，且 2048 字节扇区首字节应为类型 1
        if (s + 32774 > d.Length) return false;
        return d[s + 32768] == 1;
    }

    private static bool IsLnk(ReadOnlySpan<byte> d, int s)
    {
        if (s + 20 > d.Length) return false;
        uint flags = BitConverter.ToUInt32(d.Slice(s + 20 - 4, 4));
        return (flags & 0xFFFFFF00) == 0;
    }

    private static bool IsMp4(ReadOnlySpan<byte> d, int s)
    {
        if (s + 12 > d.Length) return false;
        for (int i = 0; i < 4; i++)
        {
            byte c = d[s + 8 + i];
            if (c is < 0x20 or > 0x7E) return false;
        }
        return true;
    }

    private static bool IsPcap(ReadOnlySpan<byte> d, int s)
    {
        if (s + 24 > d.Length) return false;
        uint snap = BitConverter.ToUInt32(d.Slice(s + 16, 4));
        return snap is > 0 and <= 0x4000000;
    }

    // ── 签名表 ─────────────────────────────────────────────────────────────

    private static FileSignature[] Build()
    {
        List<FileSignature> list =
        [
            // ── 图像 ──
            S("png", "PNG 图像", FileCategory.Image, ["png"], SizeStrategy.PngToIend,
                "8 字节签名 + 块结构（IHDR/IDAT/IEND），IEND 之后的数据是 CTF 常见的藏匿点。",
                mime: "image/png", anchors: A("89 50 4E 47 0D 0A 1A 0A")),

            S("jpeg", "JPEG 图像", FileCategory.Image, ["jpg", "jpeg", "jpe"], SizeStrategy.JpegToEoi,
                "SOI(FFD8FF) 起、EOI(FFD9) 止；段间可塞入 EXIF 注释或整段附加数据。",
                mime: "image/jpeg", anchors: A("FF D8 FF")),

            S("gif", "GIF 图像", FileCategory.Image, ["gif"], SizeStrategy.GifToTrailer,
                "GIF87a/89a；多帧 GIF 每帧都可承载独立数据，末尾 0x3B 为结束符。",
                mime: "image/gif", anchors: [A("47 49 46 38 37 61"), A("47 49 46 38 39 61")]),   // "GIF87a" / "GIF89a"

            S("bmp", "BMP 位图", FileCategory.Image, ["bmp", "dib"], SizeStrategy.BmpSize,
                "未压缩位图，像素数据紧跟头部，LSB 隐写的经典载体。",
                Confidence.Medium, "image/bmp", IsBmp, A("42 4D")),

            S("webp", "WebP 图像", FileCategory.Image, ["webp"], SizeStrategy.RiffSize,
                "RIFF 容器 + VP8/VP8L/VP8X 块，可含 EXIF/XMP 块。",
                mime: "image/webp", anchors: A("52 49 46 46 00 00 00 00 57 45 42 50", 0, "FF FF FF FF 00 00 00 00 FF FF FF FF")),

            S("tiff-le", "TIFF 图像（小端）", FileCategory.Image, ["tif", "tiff"], SizeStrategy.Unknown,
                "II 标记的 TIFF；IFD 链 + 可自由扩展的 MakerNote。",
                Confidence.Medium, "image/tiff", anchors: A("49 49 2A 00")),

            S("tiff-be", "TIFF 图像（大端）", FileCategory.Image, ["tif", "tiff"], SizeStrategy.Unknown,
                "MM 标记的 TIFF。", Confidence.Medium, "image/tiff", anchors: A("4D 4D 00 2A")),

            S("ico", "ICO 图标", FileCategory.Image, ["ico"], SizeStrategy.Unknown,
                "图标容器；内嵌 PNG/BMP 数据，且常常被当作载荷容器。",
                Confidence.Medium, "image/x-icon", anchors: A("00 00 01 00")),

            S("psd", "Photoshop 文档", FileCategory.Image, ["psd"], SizeStrategy.Unknown,
                "8BPS；图层/通道数据尺寸庞大，尾部易附加数据。", mime: "image/vnd.adobe.photoshop",
                anchors: A("38 42 50 53")),

            S("heic", "HEIF/HEIC 图像", FileCategory.Image, ["heic", "heif"], SizeStrategy.Unknown,
                "ISO-BMFF 容器（ftyp 品牌 heic/heix）。", Confidence.Medium, "image/heic",
                anchors: [A("66 74 79 70 68 65 69 63", 4), A("66 74 79 70 68 65 69 78", 4)]),

            S("avif", "AVIF 图像", FileCategory.Image, ["avif"], SizeStrategy.Unknown,
                "ISO-BMFF 容器（ftyp 品牌 avif）。", Confidence.Medium, "image/avif",
                anchors: [A("66 74 79 70 61 76 69 66", 4), A("66 74 79 70 61 76 69 73", 4)]),

            S("jxl", "JPEG XL 图像", FileCategory.Image, ["jxl"], SizeStrategy.Unknown,
                "JPEG XL 容器或裸码流。", Confidence.Medium, "image/jxl",
                anchors: A("00 00 00 0C 4A 58 4C 20 0D 0A 87 0A")),

            S("dds", "DirectDraw 表面", FileCategory.Image, ["dds"], SizeStrategy.Unknown,
                "未压缩/压缩纹理，游戏资源常见。", Confidence.Medium, anchors: A("44 44 53 20")),

            S("icns", "Apple 图标", FileCategory.Image, ["icns"], SizeStrategy.Unknown,
                "macOS 图标容器。", Confidence.Medium, anchors: A("69 63 6E 73")),

            S("qoi", "Quite OK Image", FileCategory.Image, ["qoi"], SizeStrategy.Unknown,
                "无压缩损失的轻量图像格式。", anchors: A("71 6F 69 66")),

            S("xcf", "GIMP 工程", FileCategory.Image, ["xcf"], SizeStrategy.Unknown,
                "GIMP 原生工程文件。", anchors: A("67 69 6D 70 20 78 63 66 20")),

            S("bpg", "BPG 图像", FileCategory.Image, ["bpg"], SizeStrategy.Unknown,
                "基于 HEVC 的图像格式。", anchors: A("42 50 47 FB")),

            // ── 音频 ──
            S("wav", "WAVE 音频", FileCategory.Audio, ["wav"], SizeStrategy.RiffSize,
                "RIFF 容器 + fmt/data 块。16 位 PCM 样本低位是最常见的音频隐写通道。",
                mime: "audio/wav",
                anchors: A("52 49 46 46 00 00 00 00 57 41 56 45", 0, "FF FF FF FF 00 00 00 00 FF FF FF FF")),

            S("aiff", "AIFF 音频", FileCategory.Audio, ["aif", "aiff"], SizeStrategy.Unknown,
                "IFF 容器（大端）。", Confidence.Medium,
                anchors: [A("46 4F 52 4D 00 00 00 00 41 49 46 46", 0, "FF FF FF FF 00 00 00 00 FF FF FF FF"),
                        A("46 4F 52 4D 00 00 00 00 41 49 46 43", 0, "FF FF FF FF 00 00 00 00 FF FF FF FF")]),

            S("flac", "FLAC 无损音频", FileCategory.Audio, ["flac"], SizeStrategy.Unknown,
                "fLaC + 元数据块；PADDING/VORBIS_COMMENT 块常被用作藏匿区。",
                mime: "audio/flac", anchors: A("66 4C 61 43")),

            S("ogg", "Ogg 容器", FileCategory.Audio, ["ogg", "oga", "opus"], SizeStrategy.Unknown,
                "OggS 页结构（Vorbis/Opus/FLAC 封装），页间可插入垃圾数据。",
                mime: "audio/ogg", anchors: A("4F 67 67 53")),

            S("mp3-id3", "MP3（含 ID3 标签）", FileCategory.Audio, ["mp3"], SizeStrategy.Unknown,
                "ID3v2 头起；标签内可藏整段文件，TAG/APEv2 可追加在尾部。",
                mime: "audio/mpeg", anchors: A("49 44 33")),

            S("mp3-frame", "MP3 音频帧", FileCategory.Audio, ["mp3"], SizeStrategy.Unknown,
                "MPEG 帧同步字（11 位全 1）；帧级隐写可藏在帧头填充位。",
                Confidence.Low, "audio/mpeg", IsMp3Frame, A("FF E0", 0, "FF E0")),

            S("midi", "MIDI 音频", FileCategory.Audio, ["mid", "midi"], SizeStrategy.Unknown,
                "MThd 块；音符数据量大，尾部易附加。", Confidence.Medium, "audio/midi",
                anchors: A("4D 54 68 64")),

            S("amr", "AMR 语音", FileCategory.Audio, ["amr"], SizeStrategy.Unknown,
                "自适应多速率语音。#!AMR 头。", anchors: A("23 21 41 4D 52")),

            S("ape", "Monkey's Audio", FileCategory.Audio, ["ape"], SizeStrategy.Unknown,
                "MAC 头（Monkey's Audio），无损压缩音频。", Confidence.Medium, anchors: A("4D 41 43 20")),

            S("asf", "ASF/WMA 媒体", FileCategory.Video, ["wma", "wmv", "asf"], SizeStrategy.Unknown,
                "ASF 对象容器（微软媒体）。", anchors: A("30 26 B2 75 8E 66 CF 11 A6 D9 00 AA 00 62 CE 6C")),

            // ── 视频 ──
            S("mp4", "MP4/MOV 视频", FileCategory.Video, ["mp4", "m4v", "mov"], SizeStrategy.Unknown,
                "ISO-BMFF 盒子结构（ftyp/moov/mdat）；mdat 后常有未引用数据。",
                Confidence.Medium, "video/mp4", IsMp4,
                A("66 74 79 70 69 73 6F 6D", 4), A("66 74 79 70 6D 70 34 32", 4),
                A("66 74 79 70 6D 70 34 31", 4), A("66 74 79 70 71 74 20 20", 4),
                A("66 74 79 70 4D 34 41 20", 4), A("66 74 79 70 33 67 70", 4)),

            S("mkv", "Matroska/WebM", FileCategory.Video, ["mkv", "webm"], SizeStrategy.EbmlSize,
                "EBML 容器；1A45DFA3 起始，元素长度可递归解析。", Confidence.High, "video/x-matroska",
                anchors: A("1A 45 DF A3")),

            S("avi", "AVI 视频", FileCategory.Video, ["avi"], SizeStrategy.RiffSize,
                "RIFF 容器 + AVI 块。", Confidence.High, "video/x-msvideo",
                anchors: A("52 49 46 46 00 00 00 00 41 56 49 20", 0, "FF FF FF FF 00 00 00 00 FF FF FF FF")),

            S("flv", "Flash 视频", FileCategory.Video, ["flv"], SizeStrategy.Unknown,
                "FLV 容器；标签结构中可插入脚本数据。", anchors: A("46 4C 56 01")),

            S("mpeg-ps", "MPEG 节目流", FileCategory.Video, ["mpg", "mpeg"], SizeStrategy.Unknown,
                "MPEG-1/2 节目流起始码。", Confidence.Medium, anchors: A("00 00 01 BA")),

            S("realmedia", "RealMedia", FileCategory.Video, ["rm", "rmvb"], SizeStrategy.Unknown,
                ".RMF 容器。", Confidence.Medium, anchors: A("2E 52 4D 46")),

            // ── 压缩/归档 ──
            S("zip", "ZIP 归档", FileCategory.Archive, ["zip"], SizeStrategy.ZipToEocd,
                "PK\\x03\\x04 本地文件头。CTF 里最常见的尾部附加载荷，也可能是加密后伪装成其他文件。",
                mime: "application/zip", anchors: A("50 4B 03 04")),

            S("zip-empty", "ZIP 归档（空）", FileCategory.Archive, ["zip"], SizeStrategy.ZipToEocd,
                "只有中央目录结束记录的空归档。", Confidence.Medium, "application/zip",
                anchors: A("50 4B 05 06")),

            S("zip-spanned", "ZIP 分卷标记", FileCategory.Archive, ["zip"], SizeStrategy.ZipToEocd,
                "分卷归档标记（PK\\x07\\x08）。", Confidence.Medium, anchors: A("50 4B 07 08")),

            S("gzip", "GZIP 压缩流", FileCategory.Archive, ["gz", "tgz"], SizeStrategy.GzipStream,
                "1F8B08 头；末尾 4 字节 ISIZE 为原始长度，可作完整性校验。",
                mime: "application/gzip", anchors: A("1F 8B 08")),

            S("bzip2", "BZIP2 压缩流", FileCategory.Archive, ["bz2"], SizeStrategy.Unknown,
                "BZh 头 + 块魔数。", mime: "application/x-bzip2", anchors: A("42 5A 68")),

            S("xz", "XZ 压缩流", FileCategory.Archive, ["xz"], SizeStrategy.XzStream,
                "FD 37 7A 58 5A 00 魔数，尾部有块索引与结束标记。",
                mime: "application/x-xz", anchors: A("FD 37 7A 58 5A 00")),

            S("7z", "7-Zip 归档", FileCategory.Archive, ["7z"], SizeStrategy.SevenZipStream,
                "37 7A BC AF 27 1C 头；头部含下一段头的偏移与长度，可精确算出文件结束。",
                mime: "application/x-7z-compressed", anchors: A("37 7A BC AF 27 1C")),

            S("rar4", "RAR 归档（v4）", FileCategory.Archive, ["rar"], SizeStrategy.RarStream,
                "Rar!\\x1A\\x07\\x00 头，块结构可遍历到结束块。",
                mime: "application/vnd.rar", anchors: A("52 61 72 21 1A 07 00")),

            S("rar5", "RAR 归档（v5）", FileCategory.Archive, ["rar"], SizeStrategy.RarStream,
                "RAR5 头，含 CRC32 与块长度。",
                mime: "application/vnd.rar", anchors: A("52 61 72 21 1A 07 01 00")),

            S("tar", "TAR 归档", FileCategory.Archive, ["tar"], SizeStrategy.TarBlocks,
                "偏移 257 处 'ustar'；512 字节块，两个全零块表示结束。",
                mime: "application/x-tar", anchors: A("75 73 74 61 72 00", 257)),

            S("zstd", "Zstandard 压缩流", FileCategory.Archive, ["zst"], SizeStrategy.ZstdStream,
                "28 B5 2F FD 帧头，帧头可含内容尺寸。",
                mime: "application/zstd", anchors: A("28 B5 2F FD")),

            S("lz4", "LZ4 压缩流", FileCategory.Archive, ["lz4"], SizeStrategy.Unknown,
                "LZ4 帧格式魔数 04 22 4D 18。", Confidence.Medium, anchors: A("04 22 4D 18")),

            S("cab", "CAB 归档", FileCategory.Archive, ["cab"], SizeStrategy.Unknown,
                "MSCF 微软压缩包。", anchors: A("4D 53 43 46")),

            S("zlib", "zlib 压缩流", FileCategory.Archive, [], SizeStrategy.Unknown,
                "裸 deflate 流（78 01/9C/DA 等）。常出现在 PNG IDAT、PDF FlateDecode 与自定义容器里。",
                Confidence.Low, validate: IsZlib, anchors: [A("78 01"), A("78 9C"), A("78 DA"), A("78 5E")]),

            S("iso", "ISO 9660 光盘镜像", FileCategory.Disk, ["iso"], SizeStrategy.Unknown,
                "偏移 32769 处 CD001 卷描述符。",
                validate: IsIso9660, anchors: A("43 44 30 30 31", 32769)),

            S("cpio", "CPIO 归档", FileCategory.Archive, ["cpio"], SizeStrategy.Unknown,
                "070701/070702 新式 ASCII 头（initramfs 常用）。",
                anchors: [A("30 37 30 37 30 31"), A("30 37 30 37 30 32")]),

            S("ar", "ar/DEB 归档", FileCategory.Archive, ["a", "deb"], SizeStrategy.Unknown,
                "!<arch> 归档头。", anchors: A("21 3C 61 72 63 68 3E")),

            S("rpm", "RPM 包", FileCategory.Archive, ["rpm"], SizeStrategy.Unknown,
                "RPM 包魔数 ED AB EE DB。", anchors: A("ED AB EE DB")),

            S("lzma", "LZMA 压缩流", FileCategory.Archive, ["lzma"], SizeStrategy.Unknown,
                "LZMA1 裸流头（属性字节 0x5D + 字典大小）。",
                Confidence.Low, anchors: A("5D 00 00 80 00")),

            // ── 文档 ──
            S("pdf", "PDF 文档", FileCategory.Document, ["pdf"], SizeStrategy.PdfToEof,
                "%PDF 头 + 对象/流结构；FlateDecode 流、增量更新区、%%EOF 之后都可能藏东西。",
                mime: "application/pdf", anchors: A("25 50 44 46 2D")),

            S("ole", "OLE 复合文档", FileCategory.Document, ["doc", "xls", "ppt", "msi"], SizeStrategy.Unknown,
                "D0CF11E0 复合文件（老版 Office / MSI），流可隐藏数据。",
                anchors: A("D0 CF 11 E0 A1 B1 1A E1")),

            S("rtf", "RTF 文档", FileCategory.Document, ["rtf"], SizeStrategy.Unknown,
                "{\\rtf 文本格式，可内嵌十六进制对象。", Confidence.Medium,
                anchors: A("7B 5C 72 74 66")),

            S("chm", "CHM 帮助文档", FileCategory.Document, ["chm"], SizeStrategy.Unknown,
                "ITSF 头，内部为 LZX 压缩的 ITSF 存储。", anchors: A("49 54 53 46")),

            S("mobi", "MOBI 电子书", FileCategory.Document, ["mobi", "azw"], SizeStrategy.Unknown,
                "偏移 60 处 BOOKMOBI 标识。", Confidence.Medium, anchors: A("42 4F 4F 4B 4D 4F 42 49", 60)),

            S("djvu", "DjVu 文档", FileCategory.Document, ["djvu"], SizeStrategy.Unknown,
                "AT&T FORM 容器。", Confidence.Medium, anchors: A("41 54 26 54 46 4F 52 4D")),

            S("postscript", "PostScript", FileCategory.Document, ["ps", "eps"], SizeStrategy.Unknown,
                "%!PS 头。", Confidence.Medium, anchors: A("25 21 50 53")),

            // ── 可执行/代码 ──
            S("elf", "ELF 可执行/目标文件", FileCategory.Executable, ["elf", "so", "o"], SizeStrategy.Unknown,
                "\\x7FELF；节表之后可追加数据（运行不受影响）。",
                validate: IsElf, anchors: A("7F 45 4C 46")),

            S("pe", "PE 可执行文件", FileCategory.Executable, ["exe", "dll", "sys"], SizeStrategy.Unknown,
                "MZ + PE 头（e_lfanew 指向 PE\\0\\0）。覆盖层（overlay）是经典的藏匿位置。",
                Confidence.Medium, validate: IsPe, anchors: A("4D 5A")),

            S("macho32-be", "Mach-O 可执行文件（32 位）", FileCategory.Executable, ["macho"], SizeStrategy.Unknown,
                "FEEDFACE 魔数。", anchors: A("FE ED FA CE")),

            S("macho64-be", "Mach-O 可执行文件（64 位）", FileCategory.Executable, ["macho"], SizeStrategy.Unknown,
                "FEEDFACF 魔数。", anchors: A("FE ED FA CF")),

            S("macho32-le", "Mach-O 可执行文件（32 位，小端）", FileCategory.Executable, ["macho"], SizeStrategy.Unknown,
                "CEFAEDFE 魔数。", anchors: A("CE FA ED FE")),

            S("macho64-le", "Mach-O 可执行文件（64 位，小端）", FileCategory.Executable, ["macho"], SizeStrategy.Unknown,
                "CFFAEDFE 魔数。", anchors: A("CF FA ED FE")),

            S("macho-fat", "Mach-O 通用二进制", FileCategory.Executable, ["macho"], SizeStrategy.Unknown,
                "CAFEBABE 胖二进制（与 Java class 同魔数，按架构数区分）。",
                Confidence.Medium, validate: IsMachFat, anchors: A("CA FE BA BE")),

            S("java-class", "Java 字节码", FileCategory.Executable, ["class"], SizeStrategy.Unknown,
                "CAFEBABE + 次/主版本号。", validate: IsJavaClass, anchors: A("CA FE BA BE")),

            S("dex", "Android DEX", FileCategory.Executable, ["dex"], SizeStrategy.Unknown,
                "dex\\n035\\0 头。", anchors: A("64 65 78 0A 30 33 35 00")),

            S("wasm", "WebAssembly 模块", FileCategory.Executable, ["wasm"], SizeStrategy.Unknown,
                "\\0asm 魔数 + 版本 1。", anchors: A("00 61 73 6D 01 00 00 00")),

            S("lnk", "Windows 快捷方式", FileCategory.Executable, ["lnk"], SizeStrategy.Unknown,
                "Shell Link 头，常被用来藏命令或载荷。",
                Confidence.Medium, validate: IsLnk, anchors: A("4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46")),

            S("shell-script", "Shell 脚本", FileCategory.Executable, ["sh", "bash"], SizeStrategy.Unknown,
                "Shebang 起始。", Confidence.Medium, anchors: [A("23 21 2F 62 69 6E 2F"), A("23 21 2F 75 73 72 2F 62 69 6E 2F 65 6E 76")]),

            S("python-script", "Python 脚本", FileCategory.Executable, ["py"], SizeStrategy.Unknown,
                "Shebang 指向 python。", Confidence.Medium, anchors: A("23 21 2F 75 73 72 2F 62 69 6E 2F 70 79 74 68 6F 6E")),

            // ── 数据库/取证 ──
            S("sqlite", "SQLite 数据库", FileCategory.Database, ["db", "sqlite", "sqlite3"], SizeStrategy.SqlitePages,
                "SQLite format 3\\0；页面结构可解析，删除记录仍残留在空闲页里。",
                mime: "application/vnd.sqlite3", anchors: A("53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00")),

            S("pcap", "PCAP 抓包文件", FileCategory.Network, ["pcap"], SizeStrategy.PcapStream,
                "经典 pcap（按幻数区分大小端），按包记录顺序遍历。",
                validate: IsPcap, anchors: [A("D4 C3 B2 A1"), A("A1 B2 C3 D4"), A("4D 3C B2 A1"), A("A1 B2 3C 4D")]),

            S("pcapng", "PCAP-NG 抓包文件", FileCategory.Network, ["pcapng"], SizeStrategy.Unknown,
                "0A0D0D0A 块结构抓包文件。", anchors: A("0A 0D 0D 0A")),

            S("evtx", "Windows 事件日志", FileCategory.Database, ["evtx"], SizeStrategy.Unknown,
                "ElfFile\\0 头，取证分析常用。", anchors: A("45 6C 66 46 69 6C 65 00")),

            S("regf", "Windows 注册表蜂巢", FileCategory.Database, ["dat", "hiv"], SizeStrategy.Unknown,
                "regf 头。", Confidence.Medium, anchors: A("72 65 67 66")),

            S("ese", "ESE 数据库", FileCategory.Database, ["edb"], SizeStrategy.Unknown,
                "可扩展存储引擎（AD/NTDS 数据库）。", Confidence.Low, anchors: A("EF CD AB 89")),

            // ── 字体 ──
            S("ttf", "TrueType 字体", FileCategory.Font, ["ttf"], SizeStrategy.Unknown,
                "00 01 00 00 + 表目录；字形数据可被替换为载荷。",
                Confidence.Medium, validate: IsTtf, anchors: A("00 01 00 00")),

            S("ttc", "TrueType 字体集合", FileCategory.Font, ["ttc"], SizeStrategy.Unknown,
                "ttcf 集合头。", Confidence.Medium, anchors: A("74 74 63 66")),

            S("otf", "OpenType 字体", FileCategory.Font, ["otf"], SizeStrategy.Unknown,
                "OTTO（CFF 轮廓）字体。", Confidence.Medium, anchors: A("4F 54 54 4F")),

            S("woff", "WOFF 字体", FileCategory.Font, ["woff"], SizeStrategy.Unknown,
                "wOFF 网页字体。", anchors: A("77 4F 46 46")),

            S("woff2", "WOFF2 字体", FileCategory.Font, ["woff2"], SizeStrategy.Unknown,
                "wOF2 网页字体（Brotli 压缩）。", anchors: A("77 4F 46 32")),

            // ── 加密/密钥 ──
            S("pem", "PEM 编码密钥/证书", FileCategory.Crypto, ["pem", "crt", "key"], SizeStrategy.Unknown,
                "-----BEGIN ...----- 文本块，直接可读。",
                anchors: A("2D 2D 2D 2D 2D 42 45 47 49 4E 20")),

            S("openssh-key", "OpenSSH 私钥", FileCategory.Crypto, ["key"], SizeStrategy.Unknown,
                "openssh-key-v1 头。", anchors: A("6F 70 65 6E 73 73 68 2D 6B 65 79 2D 76 31")),

            S("keepass", "KeePass 数据库", FileCategory.Crypto, ["kdbx"], SizeStrategy.Unknown,
                "KDBX 签名 + 版本。", anchors: A("03 D9 A2 9A 67 FB 4B B5")),

            S("jks", "Java 密钥库", FileCategory.Crypto, ["jks"], SizeStrategy.Unknown,
                "FEEDFEED 密钥库头。", Confidence.Medium, anchors: A("FE ED FE ED")),

            S("luks", "LUKS 加密卷", FileCategory.Crypto, ["luks"], SizeStrategy.Unknown,
                "LUKS\\xBA\\xBE 卷头。", anchors: A("4C 55 4B 53 BA BE")),

            S("age", "age 加密文件", FileCategory.Crypto, ["age"], SizeStrategy.Unknown,
                "age-encryption.org 文本头。", anchors: A("61 67 65 2D 65 6E 63 72 79 70 74 69 6F 6E 2E 6F 72 67")),

            // ── 其他容器 ──
            S("iso-bmff", "ISO-BMFF 容器", FileCategory.Video, [], SizeStrategy.Unknown,
                "通用 ftyp 盒子（品牌未知）。", Confidence.Low, validate: IsMp4, anchors: A("66 74 79 70", 4)),
        ];

        return [.. list];
    }
}
