using System.Text;

namespace HexLens.Core.Analysis;

/// <summary>字符串编码类型。</summary>
public enum StringKind
{
    Ascii,
    Utf16Le,
    Utf16Be,
}

/// <summary>提取出的字符串。</summary>
public sealed record ExtractedString(int Offset, string Text, StringKind Kind, int ByteLength)
{
    /// <summary>显示用前缀（含偏移与编码）。</summary>
    public string Describe => $"0x{Offset:X8} [{Kind}] {Text}";
}

/// <summary>
/// 字符串提取（strings 命令的等价物，额外支持 UTF-16 与"可疑内容"标注）。
/// </summary>
public static class StringExtractor
{
    /// <summary>默认最短字符串长度。</summary>
    public const int DefaultMinLength = 6;

    /// <summary>标注为"值得注意"的关键词（CTF 常见标记）。</summary>
    private static readonly string[] SuspiciousKeywords =
    [
        "flag", "ctf", "key", "pass", "secret", "token", "admin", "hidden", "zip", "rar",
        "base64", "begin", "ssh-rsa", "http://", "https://", "password", "encrypt", "aes",
    ];

    /// <summary>
    /// 提取可打印字符串。
    /// </summary>
    /// <param name="data">缓冲区。</param>
    /// <param name="minLength">最短长度。</param>
    /// <param name="maxResults">结果上限。</param>
    /// <param name="includeWide">是否同时提取 UTF-16（宽字符）。</param>
    public static List<ExtractedString> Extract(
        ReadOnlySpan<byte> data,
        int minLength = DefaultMinLength,
        int maxResults = 20000,
        bool includeWide = true)
    {
        var results = new List<ExtractedString>();
        if (data.Length == 0) return results;

        ExtractAscii(data, Math.Max(2, minLength), maxResults, results);
        if (includeWide && results.Count < maxResults)
            ExtractUtf16(data, Math.Max(2, minLength), maxResults, results);

        results.Sort(static (a, b) => a.Offset.CompareTo(b.Offset));
        return results;
    }

    /// <summary>判断字符串是否含可疑关键词（CTF 里常直接就是提示）。</summary>
    public static bool IsSuspicious(string text)
    {
        foreach (string keyword in SuspiciousKeywords)
        {
            if (text.Contains(keyword, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static void ExtractAscii(ReadOnlySpan<byte> data, int minLength, int maxResults, List<ExtractedString> results)
    {
        var sb = new StringBuilder();
        int start = 0;

        for (int i = 0; i < data.Length; i++)
        {
            byte b = data[i];
            if (b is >= 0x20 and < 0x7F || b == 0x09)
            {
                if (sb.Length == 0) start = i;
                sb.Append((char)b);
            }
            else
            {
                if (sb.Length >= minLength)
                    results.Add(new ExtractedString(start, sb.ToString(), StringKind.Ascii, sb.Length));
                sb.Clear();
                if (results.Count >= maxResults) return;
            }
        }

        if (sb.Length >= minLength && results.Count < maxResults)
            results.Add(new ExtractedString(start, sb.ToString(), StringKind.Ascii, sb.Length));
    }

    private static void ExtractUtf16(ReadOnlySpan<byte> data, int minLength, int maxResults, List<ExtractedString> results)
    {
        ExtractUtf16Oriented(data, minLength, maxResults, results, littleEndian: true);
        if (results.Count < maxResults)
            ExtractUtf16Oriented(data, minLength, maxResults, results, littleEndian: false);
    }

    private static void ExtractUtf16Oriented(
        ReadOnlySpan<byte> data, int minLength, int maxResults, List<ExtractedString> results, bool littleEndian)
    {
        var sb = new StringBuilder();
        int start = 0;

        for (int i = 0; i + 1 < data.Length; i += 2)
        {
            byte low = littleEndian ? data[i] : data[i + 1];
            byte high = littleEndian ? data[i + 1] : data[i];

            if (high == 0 && low is >= 0x20 and < 0x7F)
            {
                if (sb.Length == 0) start = i;
                sb.Append((char)low);
            }
            else
            {
                if (sb.Length >= minLength)
                    results.Add(new ExtractedString(start, sb.ToString(), littleEndian ? StringKind.Utf16Le : StringKind.Utf16Be, sb.Length * 2));
                sb.Clear();
                if (results.Count >= maxResults) return;
            }
        }

        if (sb.Length >= minLength && results.Count < maxResults)
            results.Add(new ExtractedString(start, sb.ToString(), littleEndian ? StringKind.Utf16Le : StringKind.Utf16Be, sb.Length * 2));
    }
}
