using System.Text;
using System.Text.RegularExpressions;
using HexLens.Core.Util;

namespace HexLens.Core.Analysis;

/// <summary>搜索模式。</summary>
public enum SearchMode
{
    /// <summary>十六进制模式，支持 "??" 通配（如 "4D 5A ?? ?? 50 45"）。</summary>
    HexPattern,

    /// <summary>文本（按 UTF-8/ASCII 匹配）。</summary>
    Text,

    /// <summary>正则表达式（按 Latin-1 逐字节映射到字符）。</summary>
    Regex,
}

/// <summary>搜索请求。</summary>
/// <param name="Pattern">模式文本。</param>
/// <param name="Mode">匹配方式。</param>
/// <param name="IgnoreCase">是否忽略大小写（文本/正则）。</param>
public sealed record SearchQuery(string Pattern, SearchMode Mode = SearchMode.HexPattern, bool IgnoreCase = false);

/// <summary>一条搜索命中。</summary>
public sealed record SearchHit(int Offset, int Length, string Preview);

/// <summary>
/// 搜索：十六进制通配、文本、正则。CTF 里"找 flag 格式"和"找第二个文件头"都靠它。
/// </summary>
public static class SearchEngine
{
    /// <summary>
    /// 解析十六进制模式（支持空白分隔与 "??" 通配）。
    /// "??" 表示**一个**任意字节（十六进制编辑器的通行写法），单个 "?" 视为非法。
    /// </summary>
    public static (byte[] Bytes, bool[] Mask)? ParseHexPattern(string pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern)) return null;

        var bytes = new List<byte>();
        var mask = new List<bool>();

        int i = 0;
        while (i < pattern.Length)
        {
            char c = pattern[i];
            if (char.IsWhiteSpace(c) || c is ',' or '-' or ':')
            {
                i++;
                continue;
            }

            if (c == '?')
            {
                if (i + 1 >= pattern.Length || pattern[i + 1] != '?') return null;
                bytes.Add(0);
                mask.Add(false);
                i += 2;
                continue;
            }

            if (i + 1 >= pattern.Length) return null;
            char second = pattern[i + 1];
            if (!Uri.IsHexDigit(c) || !Uri.IsHexDigit(second)) return null;

            bytes.Add(Convert.ToByte(new string([c, second]), 16));
            mask.Add(true);
            i += 2;
        }

        if (bytes.Count == 0) return null;
        return (bytes.ToArray(), mask.ToArray());
    }

    /// <summary>执行搜索。</summary>
    public static List<SearchHit> Search(ReadOnlySpan<byte> data, SearchQuery query, int maxHits = 20000)
    {
        var hits = new List<SearchHit>();
        if (data.Length == 0 || string.IsNullOrEmpty(query.Pattern)) return hits;

        switch (query.Mode)
        {
            case SearchMode.HexPattern:
                SearchHex(data, query.Pattern, hits, maxHits);
                break;

            case SearchMode.Text:
                SearchBytes(data, Encoding.UTF8.GetBytes(query.Pattern), query.IgnoreCase, hits, maxHits);
                break;

            case SearchMode.Regex:
                SearchRegex(data, query, hits, maxHits);
                break;
        }

        return hits;
    }

    private static void SearchHex(ReadOnlySpan<byte> data, string pattern, List<SearchHit> hits, int maxHits)
    {
        (byte[] Bytes, bool[] Mask)? parsed = ParseHexPattern(pattern);
        if (parsed is null) return;

        byte[] needle = parsed.Value.Bytes;
        bool[] mask = parsed.Value.Mask;
        int n = needle.Length;

        for (int i = 0; i + n <= data.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < n; j++)
            {
                if (mask[j] && data[i + j] != needle[j]) { ok = false; break; }
            }
            if (!ok) continue;

            hits.Add(new SearchHit(i, n, Preview(data, i, n)));
            if (hits.Count >= maxHits) return;
        }
    }

    private static void SearchBytes(ReadOnlySpan<byte> data, byte[] needle, bool ignoreCase, List<SearchHit> hits, int maxHits)
    {
        if (needle.Length == 0) return;

        byte[] source = data.ToArray();
        byte[] target = needle;

        if (ignoreCase)
        {
            for (int i = 0; i < source.Length; i++) source[i] = ToLower(source[i]);
            for (int i = 0; i < target.Length; i++) target[i] = ToLower(target[i]);
        }

        int pos = 0;
        while (pos <= source.Length - target.Length)
        {
            int found = source.AsSpan(pos).IndexOf(target);
            if (found < 0) break;
            int absolute = pos + found;
            hits.Add(new SearchHit(absolute, target.Length, Preview(data, absolute, target.Length)));
            if (hits.Count >= maxHits) return;
            pos = absolute + 1;
        }
    }

    private static void SearchRegex(ReadOnlySpan<byte> data, SearchQuery query, List<SearchHit> hits, int maxHits)
    {
        // 逐字节映射到 Latin-1 字符，保证偏移与字节位置一一对应
        var chars = new char[data.Length];
        for (int i = 0; i < data.Length; i++) chars[i] = (char)data[i];
        string text = new(chars);

        RegexOptions options = RegexOptions.CultureInvariant;
        if (query.IgnoreCase) options |= RegexOptions.IgnoreCase;

        Regex regex;
        try
        {
            regex = new Regex(query.Pattern, options);
        }
        catch (ArgumentException)
        {
            return;
        }

        foreach (Match match in regex.Matches(text))
        {
            if (!match.Success) continue;
            hits.Add(new SearchHit(match.Index, Math.Max(1, match.Length), match.Value));
            if (hits.Count >= maxHits) return;
        }
    }

    private static byte ToLower(byte value) => value is >= (byte)'A' and <= (byte)'Z' ? (byte)(value + 32) : value;

    private static string Preview(ReadOnlySpan<byte> data, int offset, int length)
    {
        int window = Math.Min(length + 8, data.Length - offset);
        var sb = new StringBuilder(window);
        for (int i = 0; i < window; i++)
        {
            byte b = data[offset + i];
            sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
        }
        return sb.ToString();
    }
}
