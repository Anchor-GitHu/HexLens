namespace HexLens.Core.Util;

/// <summary>CRC-32（IEEE 802.3，多项式 0xEDB88320，反射）。PNG 块校验、GZIP 尾部、ZIP 条目都用它。</summary>
public static class Crc32
{
    private static readonly uint[] Table = BuildTable();

    private static uint[] BuildTable()
    {
        var table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        return table;
    }

    /// <summary>计算一段数据的 CRC-32。</summary>
    public static uint Compute(ReadOnlySpan<byte> data, uint seed = 0)
    {
        uint crc = seed ^ 0xFFFFFFFFu;
        foreach (byte b in data)
            crc = Table[(crc ^ b) & 0xFF] ^ (crc >> 8);
        return crc ^ 0xFFFFFFFFu;
    }
}
