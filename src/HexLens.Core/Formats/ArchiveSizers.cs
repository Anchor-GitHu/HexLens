using System.IO.Compression;
using System.Text;
using HexLens.Core.Util;

namespace HexLens.Core.Formats;

/// <summary>压缩与归档容器的长度推导（ZIP/GZIP/XZ/7z/RAR/TAR/Zstd）。</summary>
public static partial class FormatSizers
{
    /// <summary>解压探测上限：防止解压炸弹把内存吃干。</summary>
    private const long MaxProbeOutput = 256L * 1024 * 1024;

    /// <summary>逐字节精确供流的 gzip 测量上限（超过则退回估算，避免 UI 卡顿）。</summary>
    private const int MaxExactGzipInput = 64 * 1024 * 1024;

    // ── ZIP ────────────────────────────────────────────────────────────────

    private static MeasureResult MeasureZip(ReadOnlySpan<byte> d, int start)
    {
        ReadOnlySpan<byte> eocdSig = [0x50, 0x4B, 0x05, 0x06];
        ReadOnlySpan<byte> cdSig = [0x50, 0x4B, 0x01, 0x02];
        ReadOnlySpan<byte> localSig = [0x50, 0x4B, 0x03, 0x04];

        // EOCD 的注释长度最大 65535，因此向后搜索 64 KiB + 22 字节即可覆盖
        int window = Math.Min(d.Length - start, 0xFFFF + 22);
        int eocd = d.Slice(start, window).LastIndexOf(eocdSig);

        var nodes = new List<StructureNode>();
        int totalEntries = 0;
        uint cdSize = 0, cdOffset = 0;
        int end = -1;

        if (eocd >= 0)
        {
            int abs = start + eocd;
            totalEntries = ByteOrder.U16LE(d, abs + 10);
            cdSize = ByteOrder.U32LE(d, abs + 12);
            cdOffset = ByteOrder.U32LE(d, abs + 16);
            int commentLen = ByteOrder.U16LE(d, abs + 20);
            end = abs + 22 + commentLen;

            nodes.Add(new StructureNode("EOCD（中央目录结束）", abs, 22 + commentLen,
                $"{totalEntries} 个条目，中央目录 {cdSize} 字节 @ 0x{cdOffset:X}，注释 {commentLen} 字节"));
        }

        // 中央目录条目：拿到文件名/大小/压缩方法/加密标志——CTF 里判"是不是加密 zip"就靠这里
        int cdAbs = start + (int)cdOffset;
        if (eocd >= 0 && cdOffset > 0 && cdAbs >= start && cdAbs < d.Length)
        {
            int pos = cdAbs;
            int count = 0;
            while (pos + 46 <= d.Length && count < 4096)
            {
                if (!d.Slice(pos, 4).SequenceEqual(cdSig)) break;

                ushort flags = ByteOrder.U16LE(d, pos + 8);
                ushort method = ByteOrder.U16LE(d, pos + 10);
                uint crc = ByteOrder.U32LE(d, pos + 16);
                uint compSize = ByteOrder.U32LE(d, pos + 20);
                uint rawSize = ByteOrder.U32LE(d, pos + 24);
                ushort nameLen = ByteOrder.U16LE(d, pos + 28);
                ushort extraLen = ByteOrder.U16LE(d, pos + 30);
                ushort commentLen2 = ByteOrder.U16LE(d, pos + 32);

                string name = nameLen > 0 && pos + 46 + nameLen <= d.Length
                    ? DecodeZipName(d.Slice(pos + 46, nameLen))
                    : "(无名)";

                bool encrypted = (flags & 0x0001) != 0;
                string methodName = method switch
                {
                    0 => "存储",
                    8 => "Deflate",
                    9 => "Deflate64",
                    12 => "BZIP2",
                    14 => "LZMA",
                    93 => "Zstd",
                    95 => "XZ",
                    98 => "PPMd",
                    99 => "AES 加密",
                    _ => $"方法 {method}",
                };

                string detail = $"{rawSize} → {compSize} 字节，{methodName}，CRC {crc:X8}"
                                + (encrypted ? "，⚠ 已加密" : string.Empty);

                nodes.Add(new StructureNode("条目 " + name, pos, 46 + nameLen + extraLen + commentLen2, detail));

                pos += 46 + nameLen + extraLen + commentLen2;
                count++;
            }
        }

        // 本地文件头：即使中央目录被破坏也能看出载荷边界
        int localCount = 0;
        int scan = start;
        while (localCount < 64)
        {
            int rel = d.Slice(scan).IndexOf(localSig);
            if (rel < 0) break;
            int abs = scan + rel;
            ushort nameLen = ByteOrder.U16LE(d, abs + 26);
            ushort extraLen = ByteOrder.U16LE(d, abs + 28);
            uint compSize = ByteOrder.U32LE(d, abs + 18);
            string name = nameLen > 0 && abs + 30 + nameLen <= d.Length
                ? DecodeZipName(d.Slice(abs + 30, nameLen))
                : "(无名)";
            nodes.Add(new StructureNode("本地头 " + name, abs, 30 + nameLen + extraLen,
                compSize > 0 ? $"压缩数据 {compSize} 字节" : "数据长度记录在数据描述符中"));
            scan = abs + 4;
            localCount++;
        }

        if (end > 0)
        {
            string note = $"ZIP 结束于 EOCD，{totalEntries} 个条目";
            if (end < d.Length) note += $"；其后还有 {d.Length - end} 字节数据（附加载荷）";
            return new MeasureResult(end - start, Confidence.High, note, nodes);
        }

        if (nodes.Count > 0)
            return new MeasureResult(d.Length - start, Confidence.Medium,
                "ZIP 缺少 EOCD（可能被截断或为流式输出），按剩余长度", nodes);

        return MeasureResult.Unknown("未找到 ZIP 结构");
    }

    private static string DecodeZipName(ReadOnlySpan<byte> raw)
    {
        // ZIP 文件名默认 CP437，这里按 UTF-8 尝试、失败退回 Latin-1 近似
        try
        {
            return new UTF8Encoding(false, true).GetString(raw);
        }
        catch
        {
            var sb = new StringBuilder(raw.Length);
            foreach (byte b in raw) sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
            return sb.ToString();
        }
    }

    // ── GZIP ───────────────────────────────────────────────────────────────

    private static MeasureResult MeasureGzip(ReadOnlySpan<byte> d, int start)
    {
        var members = new List<StructureNode>();
        int pos = start;

        while (pos + 18 <= d.Length && d[pos] == 0x1F && d[pos + 1] == 0x8B)
        {
            int memberStart = pos;
            byte method = d[pos + 2];
            byte flg = d[pos + 3];
            uint mtime = ByteOrder.U32LE(d, pos + 4);
            pos += 10;

            if ((flg & 0x04) != 0)   // FEXTRA
            {
                if (pos + 2 > d.Length) break;
                int xlen = ByteOrder.U16LE(d, pos);
                pos += 2 + xlen;
            }
            if ((flg & 0x08) != 0)   // FNAME
            {
                while (pos < d.Length && d[pos] != 0) pos++;
                pos++;
            }
            if ((flg & 0x10) != 0)   // FCOMMENT
            {
                while (pos < d.Length && d[pos] != 0) pos++;
                pos++;
            }
            if ((flg & 0x02) != 0) pos += 2;   // FHCRC

            if (pos >= d.Length) break;

            int deflateStart = pos;
            int available = d.Length - deflateStart;
            if (available > MaxExactGzipInput)
            {
                members.Add(new StructureNode("gzip 成员", memberStart, d.Length - memberStart,
                    $"deflate 数据 {available} 字节，超过精确测量上限，未解析尾部"));
                return new MeasureResult(d.Length - start, Confidence.Low,
                    "gzip 数据过大，按剩余长度估算", members);
            }

            byte[] payload = d[deflateStart..].ToArray();
            var feeder = new SingleByteStream(payload);
            long consumed;
            long outputLength = 0;
            uint crc = 0;

            try
            {
                var buffer = new byte[16384];
                using var inflate = new DeflateStream(feeder, CompressionMode.Decompress, leaveOpen: true);
                int read;
                while ((read = inflate.Read(buffer, 0, buffer.Length)) > 0)
                {
                    crc = Crc32.Compute(buffer.AsSpan(0, read), crc);
                    outputLength += read;
                    if (outputLength > MaxProbeOutput)
                    {
                        return new MeasureResult(d.Length - start, Confidence.Low,
                            "⚠ 解压输出超过 256 MiB，疑似解压炸弹，停止解析", members);
                    }
                }
                consumed = feeder.BytesRead;
            }
            catch (Exception ex)
            {
                return new MeasureResult(d.Length - start, Confidence.Low,
                    $"gzip 解压失败（{ex.GetType().Name}），按剩余长度", members);
            }

            int memberEnd = deflateStart + (int)consumed;
            string detail = $"方法 {method}，解压后 {outputLength} 字节，时间戳 0x{mtime:X8}";

            if (memberEnd + 8 <= d.Length)
            {
                uint storedCrc = ByteOrder.U32LE(d, memberEnd);
                uint storedSize = ByteOrder.U32LE(d, memberEnd + 4);
                bool crcOk = storedCrc == crc;
                bool sizeOk = storedSize == (uint)(outputLength & 0xFFFFFFFF);
                detail += crcOk && sizeOk ? "，CRC32/ISIZE 校验通过" : "，⚠ CRC32/ISIZE 校验不符";
                memberEnd += 8;
            }
            else
            {
                detail += "，尾部 CRC/ISIZE 缺失";
            }

            members.Add(new StructureNode("gzip 成员", memberStart, memberEnd - memberStart, detail));
            pos = memberEnd;
        }

        if (members.Count == 0) return MeasureResult.Unknown("gzip 头异常");

        int total = pos - start;
        bool allVerified = members.All(static n => n.Detail?.Contains("校验通过", StringComparison.Ordinal) == true);
        string note = $"gzip 解析完成，{members.Count} 个成员"
                      + (allVerified ? "，CRC32/ISIZE 校验通过" : "，⚠ CRC32/ISIZE 校验未通过");
        if (pos < d.Length) note += $"；其后还有 {d.Length - pos} 字节数据";
        return new MeasureResult(total, Confidence.High, note, members);
    }

    /// <summary>
    /// 每次只交出 1 字节的流：让 DeflateStream 按需拉取，从而精确知道 deflate 数据消耗了多少字节
    /// （gzip 的尾部 CRC/ISIZE 紧跟在 deflate 之后，多读一个字节都会算错边界）。
    /// </summary>
    private sealed class SingleByteStream(byte[] data) : Stream
    {
        private int _pos;

        public long BytesRead => _pos;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => data.Length;
        public override long Position { get => _pos; set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_pos >= data.Length || count <= 0) return 0;
            buffer[offset] = data[_pos++];
            return 1;
        }

        public override int Read(Span<byte> buffer)
        {
            if (_pos >= data.Length || buffer.Length == 0) return 0;
            buffer[0] = data[_pos++];
            return 1;
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    // ── XZ ─────────────────────────────────────────────────────────────────

    private static MeasureResult MeasureXz(ReadOnlySpan<byte> d, int start)
    {
        // 流尾：CRC32(4) + Backward Size(4) + Stream Flags(2) + "YZ"
        ReadOnlySpan<byte> yz = [0x59, 0x5A];
        int pos = start + 12;
        var nodes = new List<StructureNode>
        {
            new("XZ 流头", start, 12, "魔数 FD 37 7A 58 5A 00 + 流标志 + CRC32"),
        };

        while (pos + 2 <= d.Length)
        {
            int limit = Math.Min(d.Length, start + MaxExactGzipInput);
            int rel = d.Slice(pos, limit - pos).IndexOf(yz);
            if (rel < 0) break;

            int abs = pos + rel;
            // 校验前两字节是否为流标志（低字节应为 0，标志值只用到低 4 位）
            if (abs >= 2 && (d[abs - 2] & 0xF0) == 0)
            {
                int end = abs + 2;
                nodes.Add(new StructureNode("流尾（Stream Footer）", abs - 8, 10, "含 CRC32/Backward Size/Stream Flags/YZ"));
                string note = "XZ 流尾标记 YZ";
                if (end < d.Length) note += $"；其后还有 {d.Length - end} 字节数据";
                return new MeasureResult(end - start, Confidence.Medium, note, nodes);
            }
            pos = abs + 1;
        }

        return new MeasureResult(d.Length - start, Confidence.Low, "未定位到 XZ 流尾，按剩余长度", nodes);
    }

    // ── 7-Zip ──────────────────────────────────────────────────────────────

    private static MeasureResult Measure7Zip(ReadOnlySpan<byte> d, int start)
    {
        if (start + 32 > d.Length) return MeasureResult.Unknown("7z 签名头不完整");

        ulong nextOffset = ByteOrder.U64LE(d, start + 12);
        ulong nextSize = ByteOrder.U64LE(d, start + 20);
        byte major = d[start + 6];
        byte minor = d[start + 7];

        var nodes = new List<StructureNode>
        {
            new("7z 签名头", start, 32,
                $"版本 {major}.{minor}，下一段头偏移 {nextOffset}，长度 {nextSize}"),
        };

        long total = 32 + (long)nextOffset + (long)nextSize;
        if (total < 32 || start + total > d.Length)
            return new MeasureResult(d.Length - start, Confidence.Medium,
                "7z 声明长度超出缓冲区（可能被截断或内嵌），按剩余长度", nodes);

        if (start + total < d.Length)
            nodes.Add(new StructureNode("附加数据", start + (int)total, d.Length - start - (int)total,
                "7z 声明长度之后的数据"));

        return new MeasureResult((int)total, Confidence.High, "7z：32 字节头 + 下一段头偏移与长度", nodes);
    }

    // ── RAR ────────────────────────────────────────────────────────────────

    private static MeasureResult MeasureRar(ReadOnlySpan<byte> d, int start)
    {
        if (start + 8 > d.Length) return MeasureResult.Unknown("RAR 头不完整");

        byte versionByte = d[start + 6];
        bool isRar5 = versionByte == 0x01;
        var nodes = new List<StructureNode>();
        int pos;

        if (isRar5)
        {
            pos = start + 8;
            nodes.Add(new StructureNode("RAR5 签名", start, 8, "52 61 72 21 1A 07 01 00"));
            int guard = 0;

            while (pos < d.Length && guard++ < 100_000)
            {
                int blockStart = pos;
                pos += 4;   // CRC32
                int sizeStart = pos;
                long headerSize = ReadVint(d, ref pos);
                long headerType = ReadVint(d, ref pos);
                long flags = ReadVint(d, ref pos);
                if (headerSize < 0 || headerType < 0 || flags < 0) break;

                long extraSize = (flags & 0x0001) != 0 ? ReadVint(d, ref pos) : 0;
                long dataSize = (flags & 0x0002) != 0 ? ReadVint(d, ref pos) : 0;
                if (extraSize < 0 || dataSize < 0) break;

                long blockEnd = sizeStart + headerSize + dataSize;
                if (blockEnd > d.Length) break;

                nodes.Add(new StructureNode($"RAR5 块（类型 {headerType}）", blockStart, (int)(blockEnd - blockStart),
                    $"头 {headerSize} 字节，数据 {dataSize} 字节"));

                pos = (int)blockEnd;
                if (headerType == 5)   // 归档结束块
                {
                    string note = "RAR5 归档结束块";
                    if (pos < d.Length) note += $"；其后还有 {d.Length - pos} 字节数据";
                    return new MeasureResult(pos - start, Confidence.High, note, nodes);
                }
            }

            return new MeasureResult(Math.Min(pos, d.Length) - start, Confidence.Medium, "RAR5 解析中断", nodes);
        }

        pos = start + 7;
        nodes.Add(new StructureNode("RAR4 签名", start, 7, "52 61 72 21 1A 07 00"));
        int guard4 = 0;

        while (pos + 7 <= d.Length && guard4++ < 100_000)
        {
            int blockStart = pos;
            byte type = d[pos + 2];
            ushort headFlags = ByteOrder.U16LE(d, pos + 3);
            ushort headSize = ByteOrder.U16LE(d, pos + 5);
            if (headSize < 7) break;

            long dataSize = (headFlags & 0x8000) != 0 && pos + 11 <= d.Length
                ? ByteOrder.U32LE(d, pos + 7)
                : 0;

            long blockEnd = pos + (long)headSize + dataSize;
            if (blockEnd > d.Length) break;

            nodes.Add(new StructureNode($"RAR4 块（类型 0x{type:X2}）", blockStart, (int)(blockEnd - blockStart),
                $"头 {headSize} 字节，数据 {dataSize} 字节"));

            pos = (int)blockEnd;
            if (type == 0x7B)
            {
                string note = "RAR4 归档结束块";
                if (pos < d.Length) note += $"；其后还有 {d.Length - pos} 字节数据";
                return new MeasureResult(pos - start, Confidence.High, note, nodes);
            }
        }

        return new MeasureResult(Math.Min(pos, d.Length) - start, Confidence.Medium, "RAR4 解析中断", nodes);
    }

    private static long ReadVint(ReadOnlySpan<byte> d, ref int pos)
    {
        long value = 0;
        int shift = 0;
        for (int i = 0; i < 10 && pos < d.Length; i++)
        {
            byte b = d[pos++];
            value |= (long)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) return value;
            shift += 7;
        }
        return -1;
    }

    // ── TAR ────────────────────────────────────────────────────────────────

    private static MeasureResult MeasureTar(ReadOnlySpan<byte> d, int start)
    {
        int pos = start;
        var nodes = new List<StructureNode>();
        int zeroBlocks = 0;
        int entries = 0;

        while (pos + 512 <= d.Length)
        {
            bool allZero = true;
            for (int i = 0; i < 512; i++)
            {
                if (d[pos + i] != 0) { allZero = false; break; }
            }

            if (allZero)
            {
                zeroBlocks++;
                pos += 512;
                if (zeroBlocks >= 2)
                {
                    string note = $"TAR 结束（两个零块），{entries} 个条目";
                    if (pos < d.Length) note += $"；其后还有 {d.Length - pos} 字节数据";
                    return new MeasureResult(pos - start, Confidence.High, note, nodes);
                }
                continue;
            }

            zeroBlocks = 0;
            string name = ByteOrder.Ascii(d, pos, 100);
            long size = ParseTarOctal(d, pos + 124, 12);
            char typeFlag = (char)d[pos + 156];
            string typeName = typeFlag switch
            {
                '0' or '\0' => "普通文件",
                '5' => "目录",
                '2' => "符号链接",
                '1' => "硬链接",
                'L' => "长文件名",
                'x' => "扩展头",
                'g' => "全局扩展头",
                _ => $"类型 {typeFlag}",
            };

            long dataBlocks = size > 0 ? (size + 511) / 512 * 512 : 0;
            nodes.Add(new StructureNode(string.IsNullOrEmpty(name) ? "(无名)" : name, pos,
                (int)(512 + dataBlocks), $"{typeName}，{size} 字节"));
            entries++;

            long next = pos + 512L + dataBlocks;
            if (next > d.Length) break;
            pos = (int)next;
            if (entries > 200_000) break;
        }

        return new MeasureResult(Math.Min(pos, d.Length) - start, Confidence.Medium, $"TAR 扫描中断，{entries} 个条目", nodes);
    }

    private static long ParseTarOctal(ReadOnlySpan<byte> d, int offset, int length)
    {
        long value = 0;
        bool any = false;
        for (int i = 0; i < length && offset + i < d.Length; i++)
        {
            byte b = d[offset + i];
            if (b == 0 || b == (byte)' ') break;
            if (b is < (byte)'0' or > (byte)'7') continue;
            value = value * 8 + (b - (byte)'0');
            any = true;
        }
        return any ? value : 0;
    }

    // ── Zstandard ──────────────────────────────────────────────────────────

    private static MeasureResult MeasureZstd(ReadOnlySpan<byte> d, int start)
    {
        if (start + 6 > d.Length) return MeasureResult.Unknown("Zstd 帧头不完整");

        int pos = start + 4;
        byte descriptor = d[pos++];
        bool singleSegment = (descriptor & 0x20) != 0;
        int dictIdFlag = descriptor & 0x03;
        int frameContentSizeFlag = (descriptor >> 6) & 0x03;

        if (!singleSegment) pos += 1;   // Window Descriptor
        pos += dictIdFlag switch { 0 => 0, 1 => 1, 2 => 2, _ => 4 };
        int fcsSize = frameContentSizeFlag switch
        {
            0 => singleSegment ? 1 : 0,
            1 => 2,
            2 => 4,
            _ => 8,
        };
        pos += fcsSize;

        var nodes = new List<StructureNode>
        {
            new("Zstd 帧头", start, pos - start,
                $"描述符 0x{descriptor:X2}，{(singleSegment ? "单段" : "多段")}，字典 ID {(dictIdFlag == 0 ? "无" : "有")}"),
        };

        int blocks = 0;
        while (pos + 3 <= d.Length)
        {
            int header = d[pos] | (d[pos + 1] << 8) | (d[pos + 2] << 16);
            bool lastBlock = (header & 1) != 0;
            int blockType = (header >> 1) & 3;
            int blockSize = header >> 3;

            if (blockType == 3) return new MeasureResult(d.Length - start, Confidence.Low, "Zstd 保留块类型，按剩余长度", nodes);

            pos += 3 + blockSize;
            blocks++;
            if (lastBlock)
            {
                int end = Math.Min(pos, d.Length);
                string note = $"Zstd 帧结束，{blocks} 个块";
                if (end < d.Length) note += $"；其后还有 {d.Length - end} 字节数据";
                return new MeasureResult(end - start, Confidence.High, note, nodes);
            }
        }

        return new MeasureResult(d.Length - start, Confidence.Low, "Zstd 帧未正常结束，按剩余长度", nodes);
    }
}
