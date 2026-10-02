using System.Text;
using HexLens.Core.Util;

namespace HexLens.Core.Formats;

/// <summary>
/// 长度推导器：知道"这个文件从哪里开始"之后，算出"到哪里结束"，并顺带解析出结构树。
/// CTF 里最关键的一步往往就是它——决定尾部那一坨到底是载荷还是垃圾。
/// </summary>
public static partial class FormatSizers
{
    /// <summary>
    /// 推导指定签名的实例长度。
    /// </summary>
    /// <param name="data">整个缓冲区。</param>
    /// <param name="start">文件起点（签名命中位置）。</param>
    /// <param name="signature">命中的签名。</param>
    /// <param name="matches">全部签名命中，用于估算"到下一个文件之前"。</param>
    /// <param name="scanLimit">扫描上限（默认到缓冲区末尾）。</param>
    public static MeasureResult Measure(
        ReadOnlySpan<byte> data,
        int start,
        FileSignature signature,
        IReadOnlyList<SignatureMatch>? matches = null,
        int scanLimit = -1)
    {
        if (start < 0 || start >= data.Length)
            return MeasureResult.Unknown("起点越界");

        int limit = scanLimit > 0 ? Math.Min(scanLimit, data.Length) : data.Length;
        ReadOnlySpan<byte> view = data[..limit];

        int nextMatch = FindNextMatchOffset(matches, start, limit);

        // 少数格式的长度完全由头部字段决定，单独按 ID 分派比塞进枚举更清楚
        switch (signature.Id)
        {
            case "pe": return MeasurePe(view, start, nextMatch);
            case "elf": return MeasureElf(view, start, nextMatch);
            case "java-class": return MeasureJavaClass(view, start, nextMatch);
            case "mp4": return MeasureMp4(view, start, nextMatch);
            case "iso-bmff": return MeasureMp4(view, start, nextMatch);
        }

        return signature.Sizer switch
        {
            SizeStrategy.PngToIend => MeasurePng(view, start),
            SizeStrategy.JpegToEoi => MeasureJpeg(view, start),
            SizeStrategy.GifToTrailer => MeasureGif(view, start),
            SizeStrategy.BmpSize => MeasureBmp(view, start),
            SizeStrategy.RiffSize => MeasureRiff(view, start, signature),
            SizeStrategy.PdfToEof => MeasurePdf(view, start),
            SizeStrategy.SqlitePages => MeasureSqlite(view, start),
            SizeStrategy.PcapStream => MeasurePcap(view, start),
            SizeStrategy.EbmlSize => MeasureEbml(view, start),
            SizeStrategy.ZipToEocd => MeasureZip(view, start),
            SizeStrategy.GzipStream => MeasureGzip(view, start),
            SizeStrategy.XzStream => MeasureXz(view, start),
            SizeStrategy.SevenZipStream => Measure7Zip(view, start),
            SizeStrategy.RarStream => MeasureRar(view, start),
            SizeStrategy.TarBlocks => MeasureTar(view, start),
            SizeStrategy.ZstdStream => MeasureZstd(view, start),
            SizeStrategy.ToEndOfFile => new MeasureResult(view.Length - start, Confidence.Medium, "延伸到缓冲区末尾"),
            SizeStrategy.Fixed => new MeasureResult(signature.Anchors[0].Pattern.Length, Confidence.High, "固定长度格式"),
            _ => EstimateUnknown(view, start, nextMatch),
        };
    }

    private static int FindNextMatchOffset(IReadOnlyList<SignatureMatch>? matches, int start, int limit)
    {
        if (matches is null) return -1;
        int best = -1;
        foreach (SignatureMatch m in matches)
        {
            if (m.Offset <= start) continue;
            if (m.Offset >= limit) break;
            best = m.Offset;
            break;
        }
        return best;
    }

    private static MeasureResult EstimateUnknown(ReadOnlySpan<byte> d, int start, int nextMatch)
    {
        if (nextMatch > start)
            return new MeasureResult(nextMatch - start, Confidence.Low, "估算：延伸到下一个签名之前");
        return new MeasureResult(d.Length - start, Confidence.Low, "估算：延伸到缓冲区末尾");
    }

    // ── PNG ────────────────────────────────────────────────────────────────

    private static readonly Dictionary<string, string> PngCritical = new()
    {
        ["IHDR"] = "图像头",
        ["PLTE"] = "调色板",
        ["IDAT"] = "图像数据（zlib）",
        ["IEND"] = "图像结束",
        ["tEXt"] = "文本（未压缩）",
        ["zTXt"] = "文本（压缩）",
        ["iTXt"] = "国际化文本",
        ["tIME"] = "修改时间",
        ["gAMA"] = "伽马",
        ["cHRM"] = "色度",
        ["sRGB"] = "sRGB 意图",
        ["bKGD"] = "背景色",
        ["pHYs"] = "物理像素尺寸",
        ["sBIT"] = "有效位",
        ["acTL"] = "APNG 动画控制",
        ["fcTL"] = "APNG 帧控制",
        ["fdAT"] = "APNG 帧数据",
        ["eXIf"] = "EXIF 元数据",
    };

    private static MeasureResult MeasurePng(ReadOnlySpan<byte> d, int start)
    {
        int pos = start + 8;
        var chunks = new List<StructureNode>();
        int idatTotal = 0;

        while (pos + 12 <= d.Length)
        {
            uint len = ByteOrder.U32BE(d, pos);
            if (len > int.MaxValue - 12 || pos + 12 + (int)len > d.Length) break;

            string type = Encoding.ASCII.GetString(d.Slice(pos + 4, 4));
            int dataLen = (int)len;
            uint storedCrc = ByteOrder.U32BE(d, pos + 8 + dataLen);
            uint realCrc = Crc32.Compute(d.Slice(pos + 4, 4 + dataLen));

            string detail = type switch
            {
                "IHDR" => DescribeIhdr(d, pos + 8, dataLen),
                "tEXt" => DescribePngText(d, pos + 8, dataLen),
                "iTXt" => DescribePngText(d, pos + 8, dataLen),
                _ => $"{dataLen} 字节" + (storedCrc == realCrc ? string.Empty : $" ⚠ CRC 不符（实际 {realCrc:X8}）"),
            };

            if (PngCritical.TryGetValue(type, out string? meaning))
                detail = $"{meaning}；{detail}";
            if (type == "IDAT") idatTotal += dataLen;

            chunks.Add(new StructureNode(type, pos, 12 + dataLen, detail));
            pos += 12 + dataLen;

            if (type == "IEND")
            {
                int total = pos - start;
                string note = $"PNG 完整（IEND 结束），{chunks.Count} 个块";
                if (pos < d.Length) note += $"；其后还有 {d.Length - pos} 字节数据";
                return new MeasureResult(total, Confidence.High, note, chunks);
            }
        }

        return new MeasureResult(Math.Min(pos, d.Length) - start, Confidence.Medium,
            "PNG 块链中断（未找到 IEND）", chunks);
    }

    private static string DescribeIhdr(ReadOnlySpan<byte> d, int off, int len)
    {
        if (len < 13) return "IHDR 长度异常";
        uint w = ByteOrder.U32BE(d, off);
        uint h = ByteOrder.U32BE(d, off + 4);
        byte depth = d[off + 8];
        byte color = d[off + 9];
        byte interlace = d[off + 12];
        string colorName = color switch
        {
            0 => "灰度",
            2 => "真彩 RGB",
            3 => "索引色",
            4 => "灰度+Alpha",
            6 => "真彩 RGBA",
            _ => $"未知({color})",
        };
        return $"{w}×{h} 像素，{depth} 位，{colorName}，隔行 {(interlace == 0 ? "无" : "Adam7")}";
    }

    private static string DescribePngText(ReadOnlySpan<byte> d, int off, int len)
    {
        int end = off + len;
        int nul = -1;
        for (int i = off; i < end && i < d.Length; i++)
        {
            if (d[i] == 0) { nul = i; break; }
        }
        if (nul < 0) return "文本格式异常";
        string keyword = Encoding.ASCII.GetString(d.Slice(off, nul - off));
        string body = Encoding.UTF8.GetString(d.Slice(nul + 1, Math.Min(end, d.Length) - nul - 1));
        if (body.Length > 120) body = body[..120] + "…";
        return $"关键字 \"{keyword}\"：{body}";
    }

    // ── JPEG ───────────────────────────────────────────────────────────────

    private static readonly Dictionary<byte, string> JpegMarkers = new()
    {
        [0xC0] = "SOF0 基线帧",
        [0xC1] = "SOF1 扩展顺序帧",
        [0xC2] = "SOF2 渐进帧",
        [0xC4] = "DHT 霍夫曼表",
        [0xC8] = "JPG 保留",
        [0xDB] = "DQT 量化表",
        [0xDD] = "DRI 重启间隔",
        [0xDA] = "SOS 扫描开始",
        [0xD9] = "EOI 图像结束",
        [0xFE] = "COM 注释",
    };

    private static MeasureResult MeasureJpeg(ReadOnlySpan<byte> d, int start)
    {
        if (start + 2 >= d.Length) return MeasureResult.Unknown("数据不足");
        int pos = start + 2;
        var segments = new List<StructureNode>();

        while (pos + 4 <= d.Length)
        {
            if (d[pos] != 0xFF) { pos++; continue; }
            byte marker = d[pos + 1];
            if (marker == 0xFF) { pos++; continue; }
            if (marker == 0x00) { pos += 2; continue; }
            if (marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7)) { pos += 2; continue; }
            if (marker == 0xD9)
                return new MeasureResult(pos + 2 - start, Confidence.High,
                    $"JPEG 完整（EOI），{segments.Count} 个段", segments);

            int segLen = ByteOrder.U16BE(d, pos + 2);
            if (marker == 0xDA)
            {
                // SOS 之后是熵编码数据，逐字节扫描直到下一个非填充标记
                segments.Add(new StructureNode("SOS", pos, 2, JpegMarkers[0xDA]));
                int scan = pos + 2 + segLen;
                while (scan + 2 <= d.Length)
                {
                    if (d[scan] == 0xFF)
                    {
                        byte m2 = d[scan + 1];
                        if (m2 == 0x00 || m2 == 0xFF || (m2 >= 0xD0 && m2 <= 0xD7)) { scan += 2; continue; }
                        break;
                    }
                    scan++;
                }
                pos = scan;
                continue;
            }

            string name = marker switch
            {
                0xE0 => "APP0 (JFIF)",
                >= 0xE1 and <= 0xEF => $"APP{marker - 0xE0}",
                _ => JpegMarkers.TryGetValue(marker, out string? n) ? n : $"标记 FF{marker:X2}",
            };

            string? detail = null;
            if (marker is >= 0xE0 and <= 0xEF)
            {
                string id = ByteOrder.Ascii(d, pos + 4, Math.Min(20, Math.Max(0, segLen - 2)));
                detail = $"标识：{id}";
            }
            else if (marker == 0xFE)
            {
                string comment = ByteOrder.Ascii(d, pos + 4, Math.Min(60, Math.Max(0, segLen - 2)));
                detail = $"注释：{comment}";
            }

            segments.Add(new StructureNode(name, pos, 2 + segLen, detail));
            pos += 2 + segLen;
        }

        return new MeasureResult(Math.Min(pos, d.Length) - start, Confidence.Medium,
            "JPEG 扫描中断（未找到 EOI）", segments);
    }

    // ── GIF ────────────────────────────────────────────────────────────────

    private static MeasureResult MeasureGif(ReadOnlySpan<byte> d, int start)
    {
        if (start + 13 > d.Length) return MeasureResult.Unknown("GIF 头不完整");

        int width = ByteOrder.U16LE(d, start + 6);
        int height = ByteOrder.U16LE(d, start + 8);
        byte packed = d[start + 10];
        bool hasGct = (packed & 0x80) != 0;
        int gctSize = hasGct ? 3 * (1 << ((packed & 0x07) + 1)) : 0;

        var nodes = new List<StructureNode>
        {
            new("Header", start, 6, Encoding.ASCII.GetString(d.Slice(start, 6))),
            new("Logical Screen Descriptor", start + 6, 7,
                $"{width}×{height}，全局调色板 {(hasGct ? $"{gctSize / 3} 色" : "无")}"),
        };

        int pos = start + 13 + gctSize;
        int frames = 0;

        while (pos < d.Length)
        {
            byte block = d[pos];

            if (block == 0x3B)
            {
                nodes.Add(new StructureNode("Trailer", pos, 1, "0x3B 文件结束"));
                int total = pos + 1 - start;
                string note = $"GIF 完整，{frames} 帧";
                if (pos + 1 < d.Length) note += $"；其后还有 {d.Length - pos - 1} 字节数据";
                return new MeasureResult(total, Confidence.High, note, nodes);
            }

            if (block == 0x2C)
            {
                if (pos + 10 > d.Length) break;
                byte lp = d[pos + 9];
                int lctSize = (lp & 0x80) != 0 ? 3 * (1 << ((lp & 0x07) + 1)) : 0;
                int imgStart = pos;
                pos += 10 + lctSize;
                if (pos >= d.Length) break;
                int lzwMin = d[pos];
                pos++;
                int after = SkipGifSubBlocks(d, pos);
                nodes.Add(new StructureNode($"Image Descriptor #{frames + 1}", imgStart, after - imgStart,
                    $"{ByteOrder.U16LE(d, imgStart + 5)}×{ByteOrder.U16LE(d, imgStart + 7)}，LZW 最小码长 {lzwMin}"));
                pos = after;
                frames++;
                continue;
            }

            if (block == 0x21)
            {
                if (pos + 2 > d.Length) break;
                byte label = d[pos + 1];
                int extStart = pos;
                pos += 2;
                int after = SkipGifSubBlocks(d, pos);
                string labelName = label switch
                {
                    0xF9 => "图形控制扩展",
                    0xFE => "注释扩展",
                    0x01 => "纯文本扩展",
                    0xFF => "应用扩展",
                    _ => $"扩展 0x{label:X2}",
                };
                string? detail = label == 0xFF && pos + 11 <= d.Length
                    ? $"应用标识：{Encoding.ASCII.GetString(d.Slice(pos + 1, 8))} {Encoding.ASCII.GetString(d.Slice(pos + 9, 3))}"
                    : null;
                nodes.Add(new StructureNode(labelName, extStart, after - extStart, detail));
                pos = after;
                continue;
            }

            break;
        }

        return new MeasureResult(Math.Min(pos, d.Length) - start, Confidence.Medium,
            $"GIF 解析中断，已见 {frames} 帧", nodes);
    }

    private static int SkipGifSubBlocks(ReadOnlySpan<byte> d, int pos)
    {
        while (pos < d.Length)
        {
            int size = d[pos];
            pos++;
            if (size == 0) break;
            pos += size;
        }
        return Math.Min(pos, d.Length);
    }

    // ── BMP / RIFF ─────────────────────────────────────────────────────────

    private static MeasureResult MeasureBmp(ReadOnlySpan<byte> d, int start)
    {
        uint declared = ByteOrder.U32LE(d, start + 2);
        int dibSize = (int)ByteOrder.U32LE(d, start + 14);
        int bits = start + 28 < d.Length ? ByteOrder.U16LE(d, start + 28) : 0;
        uint dataOffset = ByteOrder.U32LE(d, start + 10);

        var nodes = new List<StructureNode>
        {
            new("BITMAPFILEHEADER", start, 14, $"声明文件大小 {declared} 字节，像素数据偏移 {dataOffset}"),
        };
        if (dibSize > 0 && start + 14 + dibSize <= d.Length)
        {
            int w = (int)ByteOrder.U32LE(d, start + 18);
            int h = (int)ByteOrder.U32LE(d, start + 22);
            nodes.Add(new StructureNode("BITMAPINFOHEADER", start + 14, dibSize,
                $"{w}×{Math.Abs(h)}，{bits} 位/像素{(h < 0 ? "，自上而下" : string.Empty)}"));
        }

        if (declared >= 14 && start + declared <= d.Length)
            return new MeasureResult((int)declared, Confidence.High, "BMP 头部声明长度", nodes);
        if (declared > d.Length - start)
            return new MeasureResult(d.Length - start, Confidence.Low, "BMP 声明长度超出缓冲区，按剩余长度", nodes);
        return new MeasureResult(d.Length - start, Confidence.Low, "BMP 未声明有效长度，按剩余长度", nodes);
    }

    private static MeasureResult MeasureRiff(ReadOnlySpan<byte> d, int start, FileSignature signature)
    {
        if (start + 12 > d.Length) return MeasureResult.Unknown("RIFF 头不完整");

        uint size = ByteOrder.U32LE(d, start + 4);
        string form = Encoding.ASCII.GetString(d.Slice(start + 8, 4));
        long total = 8L + size;

        var nodes = new List<StructureNode>
        {
            new("RIFF 头", start, 12, $"声明大小 {size} 字节，表单类型 {form}"),
        };

        int pos = start + 12;
        int limit = total <= d.Length - start ? start + (int)total : d.Length;
        while (pos + 8 <= limit)
        {
            string id = Encoding.ASCII.GetString(d.Slice(pos, 4));
            uint chunkSize = ByteOrder.U32LE(d, pos + 4);
            int padded = (int)(chunkSize + (chunkSize % 2));
            if (chunkSize > int.MaxValue || pos + 8 + padded > d.Length) break;

            string? detail = id switch
            {
                "fmt " => $"格式块：{ByteOrder.U16LE(d, pos + 8)} 格式码，{ByteOrder.U16LE(d, pos + 10)} 声道，"
                          + $"{ByteOrder.U32LE(d, pos + 12)} Hz，{ByteOrder.U16LE(d, pos + 22)} 位",
                "data" => $"音频/图像数据 {chunkSize} 字节",
                "LIST" => $"列表类型 {Encoding.ASCII.GetString(d.Slice(pos + 8, Math.Min(4, d.Length - pos - 8)))}",
                _ => $"{chunkSize} 字节",
            };
            nodes.Add(new StructureNode(id, pos, 8 + padded, detail));
            pos += 8 + padded;
        }

        if (total > 0 && start + total <= d.Length)
        {
            string note = $"RIFF 声明长度（{form}）";
            if (start + total < d.Length) note += $"；其后还有 {d.Length - start - (int)total} 字节数据";
            return new MeasureResult((int)total, Confidence.High, note, nodes);
        }
        return new MeasureResult(d.Length - start, Confidence.Low, "RIFF 声明长度超出缓冲区，按剩余长度", nodes);
    }

    // ── PDF / SQLite / PCAP ────────────────────────────────────────────────

    private static MeasureResult MeasurePdf(ReadOnlySpan<byte> d, int start)
    {
        ReadOnlySpan<byte> eof = "%%EOF"u8;
        int searchEnd = d.Length;
        int lastEof = -1;
        while (searchEnd > start)
        {
            int rel = d[..searchEnd].LastIndexOf(eof);
            if (rel < start) break;
            lastEof = rel;
            break;
        }

        var nodes = new List<StructureNode>
        {
            new("Header", start, Math.Min(8, d.Length - start), ByteOrder.Ascii(d, start, 8)),
        };

        int startxref = d.LastIndexOf("startxref"u8);
        if (startxref >= start)
            nodes.Add(new StructureNode("startxref", startxref, Math.Min(20, d.Length - startxref),
                ByteOrder.Ascii(d, startxref, 20)));

        if (lastEof < 0)
            return new MeasureResult(d.Length - start, Confidence.Low, "未找到 %%EOF，按剩余长度", nodes);

        int end = lastEof + 5;
        while (end < d.Length && (d[end] == (byte)'\r' || d[end] == (byte)'\n')) end++;
        nodes.Add(new StructureNode("%%EOF", lastEof, 5, "文件结束标记"));

        string note = "PDF 结束于 %%EOF";
        if (end < d.Length) note += $"；其后还有 {d.Length - end} 字节数据（增量更新或附加载荷）";
        return new MeasureResult(end - start, Confidence.High, note, nodes);
    }

    private static MeasureResult MeasureSqlite(ReadOnlySpan<byte> d, int start)
    {
        int pageSize = ByteOrder.U16BE(d, start + 16);
        if (pageSize == 1) pageSize = 65536;
        uint pageCount = ByteOrder.U32BE(d, start + 28);

        var nodes = new List<StructureNode>
        {
            new("SQLite 头", start, 100, $"页大小 {pageSize} 字节，页数 {pageCount}"),
        };

        if (pageSize is < 512 or > 65536 || (pageSize & (pageSize - 1)) != 0 || pageCount == 0)
            return new MeasureResult(d.Length - start, Confidence.Low, "SQLite 头字段异常，按剩余长度", nodes);

        long total = (long)pageSize * pageCount;
        if (total > d.Length - start)
            return new MeasureResult(d.Length - start, Confidence.Medium,
                $"声明 {total} 字节但缓冲区不足，按剩余长度", nodes);

        return new MeasureResult((int)total, Confidence.High, $"页大小 × 页数 = {total} 字节", nodes);
    }

    private static MeasureResult MeasurePcap(ReadOnlySpan<byte> d, int start)
    {
        if (start + 24 > d.Length) return MeasureResult.Unknown("PCAP 头不完整");

        uint be = ByteOrder.U32BE(d, start);
        bool littleEndian = be != 0xA1B2C3D4;
        var nodes = new List<StructureNode>
        {
            new("PCAP 全局头", start, 24, littleEndian ? "小端字节序" : "大端字节序"),
        };

        int pos = start + 24;
        int packets = 0;
        while (pos + 16 <= d.Length)
        {
            uint incl = littleEndian ? ByteOrder.U32LE(d, pos + 8) : ByteOrder.U32BE(d, pos + 8);
            if (incl > 0x0400_0000) break;
            long next = pos + 16L + incl;
            if (next > d.Length) break;
            pos = (int)next;
            if (++packets > 2_000_000) break;
        }

        return new MeasureResult(pos - start, Confidence.Medium, $"{packets} 个数据包", nodes);
    }

    // ── EBML（Matroska/WebM）──────────────────────────────────────────────

    private static MeasureResult MeasureEbml(ReadOnlySpan<byte> d, int start)
    {
        int pos = start;
        var nodes = new List<StructureNode>();
        int guard = 0;

        while (pos < d.Length && guard++ < 64)
        {
            int idStart = pos;
            long id = ReadEbmlValue(d, ref pos, keepMarker: true);
            if (id < 0) break;

            long size = ReadEbmlValue(d, ref pos, keepMarker: false);
            bool unknownSize = IsUnknownEbmlSize(d, idStart);

            if (unknownSize || size < 0 || pos + size > d.Length)
            {
                nodes.Add(new StructureNode($"元素 0x{id:X}", idStart, d.Length - idStart,
                    unknownSize ? "长度未定" : "长度超出缓冲区"));
                return new MeasureResult(d.Length - start, Confidence.Medium,
                    "EBML 元素长度未定，按缓冲区末尾", nodes);
            }

            string name = id switch
            {
                0x1A45DFA3 => "EBML 头",
                0x18538067 => "Segment",
                0x114D9B74 => "SeekHead",
                0x1549A966 => "Info",
                0x1654AE6B => "Tracks",
                0x1F43B675 => "Cluster",
                0x1C53BB6B => "Cues",
                _ => $"元素 0x{id:X}",
            };

            nodes.Add(new StructureNode(name, idStart, (int)(pos + size - idStart), $"{size} 字节负载"));

            if (id == 0x18538067)
                return new MeasureResult((int)(pos + size - start), Confidence.High,
                    "Matroska Segment 声明长度", nodes);

            pos = (int)(pos + size);
        }

        return new MeasureResult(Math.Min(pos, d.Length) - start, Confidence.Low, "EBML 解析中断", nodes);
    }

    private static long ReadEbmlValue(ReadOnlySpan<byte> d, ref int pos, bool keepMarker)
    {
        if (pos >= d.Length) return -1;
        byte first = d[pos];
        int len = 0;
        for (int i = 0; i < 8; i++)
        {
            if ((first & (0x80 >> i)) != 0) { len = i + 1; break; }
        }
        if (len == 0 || pos + len > d.Length) return -1;

        long value = keepMarker ? first : (first & (0xFF >> len));
        for (int i = 1; i < len; i++) value = (value << 8) | d[pos + i];
        pos += len;
        return value;
    }

    private static bool IsUnknownEbmlSize(ReadOnlySpan<byte> d, int idStart)
    {
        int pos = idStart;
        _ = ReadEbmlValue(d, ref pos, keepMarker: true);
        if (pos >= d.Length) return false;
        byte first = d[pos];
        int len = 0;
        for (int i = 0; i < 8; i++)
        {
            if ((first & (0x80 >> i)) != 0) { len = i + 1; break; }
        }
        if (len == 0 || pos + len > d.Length) return false;

        for (int i = 0; i < len; i++)
        {
            byte mask = i == 0 ? (byte)(0xFF >> len) : (byte)0xFF;
            if ((d[pos + i] & mask) != mask) return false;
        }
        return true;
    }

    // ── MP4 盒子 ───────────────────────────────────────────────────────────

    private static MeasureResult MeasureMp4(ReadOnlySpan<byte> d, int start, int nextMatch)
    {
        int pos = start;
        var boxes = new List<StructureNode>();

        while (pos + 8 <= d.Length)
        {
            long size = ByteOrder.U32BE(d, pos);
            string type = Encoding.ASCII.GetString(d.Slice(pos + 4, 4));
            int headerSize = 8;

            if (size == 1)
            {
                size = (long)ByteOrder.U64BE(d, pos + 8);
                headerSize = 16;
            }
            else if (size == 0)
            {
                size = d.Length - pos;
            }

            if (size < headerSize || pos + size > d.Length) break;

            // 不能在这里用 lambda：Span 是 ref-like 类型，无法跨匿名函数边界（CS9108）
            string? detail;
            if (type == "ftyp")
            {
                var sb = new StringBuilder("主品牌 ");
                sb.Append(ByteOrder.Ascii(d, pos + 8, 4)).Append("，兼容品牌 ");
                int brandCount = Math.Max(0, ((int)size - 16) / 4);
                for (int i = 0; i < brandCount && i < 16; i++)
                {
                    if (i > 0) sb.Append(' ');
                    sb.Append(ByteOrder.Ascii(d, pos + 16 + i * 4, 4));
                }
                detail = sb.ToString();
            }
            else
            {
                detail = type switch
                {
                    "moov" => "媒体元数据",
                    "mdat" => $"媒体数据 {size - headerSize} 字节",
                    "free" => "空闲填充（可藏数据）",
                    "uuid" => "扩展盒子",
                    _ => null,
                };
            }

            boxes.Add(new StructureNode(type, pos, (int)size, detail));
            pos += (int)size;
        }

        if (boxes.Count == 0) return EstimateUnknown(d, start, nextMatch);

        string note = $"ISO-BMFF 盒子遍历，{boxes.Count} 个盒子";
        if (pos < d.Length) note += $"；其后还有 {d.Length - pos} 字节数据";
        return new MeasureResult(pos - start, Confidence.High, note, boxes);
    }

    // ── PE / ELF / Java class ─────────────────────────────────────────────

    private static MeasureResult MeasurePe(ReadOnlySpan<byte> d, int start, int nextMatch)
    {
        if (start + 0x40 > d.Length) return EstimateUnknown(d, start, nextMatch);

        int lfanew = (int)ByteOrder.U32LE(d, start + 0x3C);
        if (lfanew <= 0 || start + lfanew + 24 > d.Length) return EstimateUnknown(d, start, nextMatch);

        int coff = start + lfanew + 4;
        ushort machine = ByteOrder.U16LE(d, coff);
        ushort sectionCount = ByteOrder.U16LE(d, coff + 2);
        ushort optSize = ByteOrder.U16LE(d, coff + 16);

        string machineName = machine switch
        {
            0x014C => "x86 (I386)",
            0x8664 => "x64 (AMD64)",
            0x01C0 => "ARM",
            0xAA64 => "ARM64",
            0x0200 => "IA64",
            _ => $"0x{machine:X4}",
        };

        var nodes = new List<StructureNode>
        {
            new("DOS 头", start, 0x40, $"e_lfanew = 0x{lfanew:X}"),
            new("PE 签名 + COFF 头", start + lfanew, 24 + optSize,
                $"{machineName}，{sectionCount} 个节"),
        };

        int sectionTable = coff + 20 + optSize;
        long maxExtent = sectionTable + sectionCount * 40L;
        var sections = new List<StructureNode>();

        for (int i = 0; i < sectionCount; i++)
        {
            int sec = sectionTable + i * 40;
            if (sec + 40 > d.Length) break;

            string name = ByteOrder.Ascii(d, sec, 8);
            uint virtualSize = ByteOrder.U32LE(d, sec + 8);
            uint rawSize = ByteOrder.U32LE(d, sec + 16);
            uint rawPointer = ByteOrder.U32LE(d, sec + 20);
            sections.Add(new StructureNode($"节 {name}", start + (int)rawPointer, (int)rawSize,
                $"虚拟 {virtualSize} 字节，文件偏移 0x{rawPointer:X}"));
            maxExtent = Math.Max(maxExtent, rawPointer + rawSize);
        }

        long declared = Math.Max(maxExtent, sectionTable + sectionCount * 40L);
        long total = Math.Min(d.Length - start, declared);

        string note = $"PE 映像声明 {total} 字节";
        if (start + total < d.Length) note += $"；其后还有 {d.Length - start - total} 字节（覆盖层/附加数据）";

        return new MeasureResult((int)total, Confidence.Medium, note, nodes);
    }

    private static MeasureResult MeasureElf(ReadOnlySpan<byte> d, int start, int nextMatch)
    {
        if (start + 0x40 > d.Length) return EstimateUnknown(d, start, nextMatch);

        bool is64 = d[start + 4] == 2;
        bool littleEndian = d[start + 5] == 1;
        ushort type = littleEndian ? ByteOrder.U16LE(d, start + 16) : ByteOrder.U16BE(d, start + 16);
        ushort machine = littleEndian ? ByteOrder.U16LE(d, start + 18) : ByteOrder.U16BE(d, start + 18);
        ushort ehsize = littleEndian
            ? ByteOrder.U16LE(d, start + (is64 ? 52 : 40))
            : ByteOrder.U16BE(d, start + (is64 ? 52 : 40));

        long shoff = is64
            ? (long)(littleEndian ? ByteOrder.U64LE(d, start + 40) : ByteOrder.U64BE(d, start + 40))
            : (littleEndian ? ByteOrder.U32LE(d, start + 32) : ByteOrder.U32BE(d, start + 32));
        ushort shentsize = littleEndian
            ? ByteOrder.U16LE(d, start + (is64 ? 58 : 46))
            : ByteOrder.U16BE(d, start + (is64 ? 58 : 46));
        ushort shnum = littleEndian
            ? ByteOrder.U16LE(d, start + (is64 ? 60 : 48))
            : ByteOrder.U16BE(d, start + (is64 ? 60 : 48));

        bool isElf64 = is64;
        string typeName = type switch { 1 => "可重定位目标", 2 => "可执行", 3 => "共享对象", 4 => "核心转储", _ => $"类型 {type}" };

        var nodes = new List<StructureNode>
        {
            new($"ELF {(is64 ? "64" : "32")} 头", start, ehsize > 0 ? ehsize : (is64 ? 64 : 52),
                $"{typeName}，{(littleEndian ? "小端" : "大端")}，机器 0x{machine:X4}"),
        };

        long declared = isElf64 ? 64 : 52;
        if (shoff > 0 && shnum > 0 && shentsize > 0)
        {
            long end = shoff + (long)shnum * shentsize;
            if (end > declared) declared = end;
            nodes.Add(new StructureNode("节头表", start + (int)shoff, (int)((long)shnum * shentsize),
                $"{shnum} 个节，每项 {shentsize} 字节"));
        }

        if (declared > d.Length - start) declared = d.Length - start;

        string note = $"ELF 声明 {declared} 字节（含节头表）";
        if (start + declared < d.Length) note += $"；其后还有 {d.Length - start - declared} 字节（附加数据）";

        return new MeasureResult((int)declared, Confidence.Medium, note, nodes);
    }

    private static MeasureResult MeasureJavaClass(ReadOnlySpan<byte> d, int start, int nextMatch)
    {
        if (start + 10 > d.Length) return EstimateUnknown(d, start, nextMatch);

        int minor = ByteOrder.U16BE(d, start + 4);
        int major = ByteOrder.U16BE(d, start + 6);
        int poolCount = ByteOrder.U16BE(d, start + 8);

        var nodes = new List<StructureNode>
        {
            new("魔数", start, 4, "CAFEBABE"),
            new("版本", start + 4, 4, $"次版本 {minor}，主版本 {major}"),
            new("常量池计数", start + 8, 2, $"{poolCount} 项（解析需完整常量池遍历）"),
        };

        return new MeasureResult(d.Length - start, Confidence.Low,
            "Java class 无长度字段，按剩余长度（尾部可附加数据）", nodes);
    }
}
