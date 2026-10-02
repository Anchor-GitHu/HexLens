using HexLens.Core.Formats;

namespace HexLens.Core.Analysis;

/// <summary>一个 XOR key 的破解候选。</summary>
/// <param name="Key">密钥字节（单字节或循环密钥）。</param>
/// <param name="Score">得分，越高越像"解出了正确内容"。</param>
/// <param name="Preview">解密结果的可读预览。</param>
/// <param name="Reason">为什么给这个分（给用户看的依据）。</param>
public sealed record XorCandidate(byte[] Key, double Score, string Preview, string Reason)
{
    /// <summary>key 的显示文本，如 <c>0x5A</c> 或 <c>5A 3C 91</c>。</summary>
    public string KeyText => Key.Length == 1
        ? $"0x{Key[0]:X2}"
        : string.Join(' ', Key.Select(static b => b.ToString("X2")));
}

/// <summary>
/// 单字节 / 短循环密钥的 XOR 暴力破解。
///
/// 为什么值得做：XOR 是 CTF 里最常见的"轻量加密"，而**密钥往往就一个字节**。
/// 256 个 key 全试一遍的算力成本可以忽略，难的是"挑出哪个是对的" ——
/// 所以这里的核心不是遍历，而是**打分**：
///   ① 解出来是否像可读文本（可打印字符占比）
///   ② 开头是否撞上已知文件签名（PNG / PDF / ZIP / ELF / PE…）
///   ③ 是否包含 flag{...} / ctf{...} 这类关键词
/// 三条都是"结构性证据"，不是"看起来像"，所以结论可以直接用。
/// </summary>
public static class XorBruteForcer
{
    /// <summary>打分时最多看前这么多字节 —— 再多也不会让判断更准，只会更慢。</summary>
    private const int ScoreWindow = 4096;

    /// <summary>预览里最多显示的字符数。</summary>
    private const int PreviewLength = 64;

    private static readonly string[] FlagMarkers =
        ["flag{", "ctf{", "FLAG{", "CTF{", "key{", "KEY{"];

    /// <summary>
    /// 遍历所有单字节 key，按得分从高到低返回候选。
    /// </summary>
    /// <param name="data">待破解的数据（通常是用户选中的区间）。</param>
    /// <param name="top">最多返回多少个候选。</param>
    public static List<XorCandidate> BruteForceSingleByte(ReadOnlySpan<byte> data, int top = 8)
    {
        var candidates = new List<XorCandidate>();
        if (data.Length == 0) return candidates;

        ReadOnlySpan<byte> window = data.Length > ScoreWindow ? data[..ScoreWindow] : data;

        for (int key = 0; key < 256; key++)
        {
            byte[] decoded = new byte[window.Length];
            for (int i = 0; i < window.Length; i++) decoded[i] = (byte)(window[i] ^ key);

            (double score, string reason) = Score(decoded);
            if (score <= 0) continue;

            candidates.Add(new XorCandidate(
                [(byte)key],
                score,
                BuildPreview(decoded),
                reason));
        }

        return candidates
            .OrderByDescending(static c => c.Score)
            .Take(top)
            .ToList();
    }

    /// <summary>
    /// 试几个常见的短循环密钥（长度 2–4），密钥取自明显的重复模式。
    ///
    /// 完整的循环密钥恢复是另一件事（要看 key 长度的周期性），
    /// 这里只覆盖 CTF 里常见的那几种"人工设的简单密钥"。
    /// </summary>
    public static List<XorCandidate> BruteForceCommonKeys(ReadOnlySpan<byte> data, int top = 4)
    {
        var results = new List<XorCandidate>();
        if (data.Length < 8) return results;

        ReadOnlySpan<byte> window = data.Length > ScoreWindow ? data[..ScoreWindow] : data;

        // 常见的人工密钥：单字节重复、递增、以及几个高频短串
        byte[][] keys =
        [
            [0x01], [0x02], [0x03], [0x7F], [0xFF],          // 常见常量
            [0xAA, 0x55], [0x55, 0xAA],                       // 交替
            [0x01, 0x02, 0x03, 0x04], [0xDE, 0xAD, 0xBE, 0xEF],
        ];

        foreach (byte[] key in keys)
        {
            byte[] decoded = new byte[window.Length];
            for (int i = 0; i < window.Length; i++) decoded[i] = (byte)(window[i] ^ key[i % key.Length]);

            (double score, string reason) = Score(decoded);
            if (score <= 0) continue;

            results.Add(new XorCandidate(key, score, BuildPreview(decoded), reason));
        }

        return results
            .OrderByDescending(static c => c.Score)
            .Take(top)
            .ToList();
    }

    /// <summary>
    /// 打分。返回 0 表示"完全不像有用内容"，直接丢弃。
    /// 分值是启发式的，但每一条都能追溯到**结构性证据**（可读比例 / 文件签名 / flag 关键词）。
    /// </summary>
    private static (double Score, string Reason) Score(ReadOnlySpan<byte> decoded)
    {
        if (decoded.Length == 0) return (0, string.Empty);

        double score = 0;
        var reasons = new List<string>();

        // ① 可打印字符占比（文本类内容的基本特征）
        int printable = 0;
        foreach (byte b in decoded)
        {
            if (b is >= 0x20 and <= 0x7E || b is 0x09 or 0x0A or 0x0D) printable++;
        }
        double printableRatio = (double)printable / decoded.Length;

        // 打印比例太低就不是文本；但也可能是二进制（交给 ② 判断），所以不直接返回 0
        score += printableRatio * 40;
        if (printableRatio >= 0.85)
        {
            reasons.Add($"可打印字符 {printableRatio:P0}");
        }

        // ② 开头撞上已知文件签名 —— 这是最强证据，直接给高分
        if (SignatureDatabase.IdentifyAt(decoded) is { } match && match.Offset == 0)
        {
            score += 60;
            reasons.Add($"开头即 {match.Signature.Name} 签名");
        }

        // ③ 出现 flag 类关键词 —— CTF 里的"标准答案"
        string head = System.Text.Encoding.ASCII.GetString(decoded[..Math.Min(decoded.Length, 512)]);
        foreach (string marker in FlagMarkers)
        {
            if (head.Contains(marker, StringComparison.Ordinal))
            {
                score += 80;
                reasons.Add($"含 {marker}");
                break;
            }
        }

        // 打分太低的直接丢，避免候选列表里塞满噪声
        if (score < 25) return (0, string.Empty);

        if (reasons.Count == 0) reasons.Add($"可打印字符 {printableRatio:P0}");

        return (score, string.Join(" · ", reasons));
    }

    /// <summary>把解密结果压成一行可读预览（不可打印字符用 · 代替）。</summary>
    private static string BuildPreview(ReadOnlySpan<byte> decoded)
    {
        int take = Math.Min(decoded.Length, PreviewLength);
        var chars = new char[take];

        for (int i = 0; i < take; i++)
        {
            byte b = decoded[i];
            chars[i] = b is >= 0x20 and <= 0x7E ? (char)b : '·';
        }

        string text = new string(chars);
        return decoded.Length > PreviewLength ? text + "…" : text;
    }
}
