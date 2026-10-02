using System.Security.Cryptography;

namespace HexLens.Core.Analysis;

/// <summary>字节频率分布与常用校验值/摘要。</summary>
public static class ByteStatistics
{
    /// <summary>256 桶频率。</summary>
    public static long[] Frequency(ReadOnlySpan<byte> data)
    {
        var counts = new long[256];
        foreach (byte b in data) counts[b]++;
        return counts;
    }

    /// <summary>
    /// 打印式文本（如 "file"/"binwalk" 那种风格）：可打印字节占比。
    /// </summary>
    public static double PrintableRatio(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0;
        int printable = 0;
        foreach (byte b in data)
        {
            if (b is >= 0x20 and < 0x7F || b is 0x09 or 0x0A or 0x0D) printable++;
        }
        return (double)printable / data.Length;
    }

    /// <summary>MD5（十六进制小写）。</summary>
    public static string Md5(ReadOnlySpan<byte> data) => Convert.ToHexStringLower(MD5.HashData(data));

    /// <summary>SHA-1。</summary>
    public static string Sha1(ReadOnlySpan<byte> data) => Convert.ToHexStringLower(SHA1.HashData(data));

    /// <summary>SHA-256。</summary>
    public static string Sha256(ReadOnlySpan<byte> data) => Convert.ToHexStringLower(SHA256.HashData(data));

    /// <summary>CRC-32。</summary>
    public static string Crc32Text(ReadOnlySpan<byte> data) => $"{Util.Crc32.Compute(data):X8}";

    /// <summary>一次算出界面要显示的摘要集合。</summary>
    public static (string Md5, string Sha1, string Sha256, string Crc32) Digests(ReadOnlySpan<byte> data)
        => (Md5(data), Sha1(data), Sha256(data), Crc32Text(data));
}
