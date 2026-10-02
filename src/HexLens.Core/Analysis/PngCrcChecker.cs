using HexLens.Core.Util;

namespace HexLens.Core.Analysis;

/// <summary>一个 CRC 校验失败的块。</summary>
/// <param name="Offset">CRC 字段在文件中的偏移。</param>
/// <param name="Length">CRC 字段长度（固定 4）。</param>
/// <param name="Name">块名（如 IHDR / IDAT）。</param>
/// <param name="Stored">文件里存的 CRC。</param>
/// <param name="Computed">按当前内容重算出来的 CRC。</param>
/// <param name="Payload">正确 CRC 的字节序（可直接写回）。</param>
public sealed record CrcMismatch(
    int Offset,
    int Length,
    string Name,
    uint Stored,
    uint Computed,
    byte[] Payload)
{
    /// <summary>期望 / 实际 的对照文本。</summary>
    public string DetailText =>
        $"{Name} 块：文件里存的是 0x{Stored:X8}，按当前内容重算应为 0x{Computed:X8}";
}

/// <summary>
/// 校验 PNG 各 chunk 的 CRC-32。
///
/// 为什么值得单独做：PNG 每个块末尾都有 4 字节 CRC，覆盖「块类型 + 块数据」。
/// CTF 里手改宽高、调色板、甚至一个像素，CRC 立刻对不上 ——
/// 而多数查看器**遇到 CRC 错就直接拒开**，看起来像"文件坏了"，
/// 实际上只要把 4 个字节重算写回即可。这是"改完能验证"的典型缺口。
/// </summary>
public static class PngCrcChecker
{
    private static readonly byte[] Signature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    /// <summary>这个缓冲区看起来是不是 PNG。</summary>
    public static bool LooksLikePng(ReadOnlySpan<byte> data)
        => data.Length >= Signature.Length && data[..Signature.Length].SequenceEqual(Signature);

    /// <summary>
    /// 遍历所有 chunk，返回 CRC 对不上的那些。
    /// 结构本身有问题（长度越界、找不到 IEND）时返回空列表 ——
    /// 那种情况该由结构分析去报，不该在这里冒充"CRC 错"。
    /// </summary>
    public static List<CrcMismatch> Check(ReadOnlySpan<byte> data)
    {
        var bad = new List<CrcMismatch>();
        if (!LooksLikePng(data)) return bad;

        int pos = Signature.Length;

        while (pos + 12 <= data.Length)
        {
            // 块头：4 字节长度（大端，只算 data）+ 4 字节类型
            uint dataLength = ReadBigEndianUInt32(data, pos);

            // 长度字段本身就可能被改坏 —— 先做边界检查，越界就停
            long chunkEnd = (long)pos + 12 + dataLength;   // header(8) + data + crc(4)
            if (chunkEnd > data.Length) break;

            int typeOffset = pos + 4;
            int dataOffset = pos + 8;
            int crcOffset = dataOffset + (int)dataLength;

            string name = DescribeType(data.Slice(typeOffset, 4));

            // CRC 覆盖「类型 + 数据」，不含长度字段
            uint computed = Crc32.Compute(data.Slice(typeOffset, 4 + (int)dataLength));
            uint stored = ReadBigEndianUInt32(data, crcOffset);

            if (computed != stored)
            {
                bad.Add(new CrcMismatch(
                    crcOffset,
                    4,
                    name,
                    stored,
                    computed,
                    // PNG 的 CRC 是**大端**存储，写回时必须按大端排
                    [(byte)(computed >> 24), (byte)(computed >> 16), (byte)(computed >> 8), (byte)computed]));
            }

            pos = (int)chunkEnd;

            if (name == "IEND") break;
        }

        return bad;
    }

    private static uint ReadBigEndianUInt32(ReadOnlySpan<byte> data, int offset)
        => ((uint)data[offset] << 24)
         | ((uint)data[offset + 1] << 16)
         | ((uint)data[offset + 2] << 8)
         | data[offset + 3];

    /// <summary>把 4 字节块类型转成可读文本；全是可打印 ASCII 才显示，否则给十六进制。</summary>
    private static string DescribeType(ReadOnlySpan<byte> type)
    {
        foreach (byte b in type)
        {
            if (b < 0x20 || b > 0x7E) return Convert.ToHexString(type);
        }
        return System.Text.Encoding.ASCII.GetString(type);
    }
}
