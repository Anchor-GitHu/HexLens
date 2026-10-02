using System.Text;

namespace HexLens.Core.Analysis;

/// <summary>
/// Base64 探测 —— **支持带前缀**的 Base64（`key` / `data:` / `flag=` …）。
///
/// 为什么单独做这一层：实战里 Base64 极少"从第一个字符就干净开头"，
/// 常见形态是 `keyV2hhdCBpcyB…`、`data:image/png;base64,iVBOR…`。
/// 含前缀时整串长度不是 4 的倍数，直接解码必然失败 ——
/// 只试偏移 0 就会把整段漏掉（snake.jpg 的真实案例：`key` + 96 字符，
/// 99 % 4 = 3，长度检查第一行就否掉了）。
///
/// 这里试 0–3 四种起始偏移，取"可读性最好"的那个，并要求可读性达标，
/// 避免把随机数据当成 Base64。
/// </summary>
public static class Base64Probe
{
    /// <summary>可读性达到这个分数才算"像文本"。</summary>
    public const int ReadableThreshold = 80;

    /// <summary>低于这个分数就认为它不是 Base64（随机字节的可打印比例约 37%）。</summary>
    public const int AcceptThreshold = 55;

    /// <summary>能接受的最短载荷（字符数）。</summary>
    public const int MinLength = 16;

    /// <summary>探测结果。</summary>
    /// <param name="Skipped">载荷前面被跳过的字符数（前缀长度）。</param>
    /// <param name="Bytes">解码结果。</param>
    /// <param name="ReadableScore">可读性打分（0–100）。</param>
    public sealed record Result(int Skipped, byte[] Bytes, int ReadableScore)
    {
        /// <summary>解码结果是否像可读文本。</summary>
        public bool IsReadableText => ReadableScore >= ReadableThreshold;
    }

    /// <summary>找出这段文本里真正能解开的 Base64 段；不是 Base64 时返回 null。</summary>
    public static Result? Find(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;

        Result? best = null;
        int bestScore = -1;

        int maxSkip = Math.Min(4, Math.Max(0, text.Length - MinLength));
        for (int skip = 0; skip <= maxSkip; skip++)
        {
            string body = text[skip..].Trim();

            // 截到第一个非 Base64 字符
            int valid = 0;
            while (valid < body.Length && IsBase64Char(body[valid])) valid++;
            body = body[..valid];
            if (body.Length < MinLength) continue;

            // 长度须为 4 的倍数：补 padding；余 1 属无解长度
            int remainder = body.Length % 4;
            if (remainder == 1) continue;
            if (remainder != 0) body += new string('=', 4 - remainder);

            byte[]? bytes = TryDecode(body);
            if (bytes is null || bytes.Length < 8) continue;

            int score = ReadableScore(bytes);
            if (score > bestScore)
            {
                bestScore = score;
                best = new Result(skip, bytes, score);
            }
        }

        return bestScore >= AcceptThreshold ? best : null;
    }

    /// <summary>把解码结果压成一行短预览（不可打印字符显示为点）。</summary>
    public static string Preview(byte[] data, int limit = 120)
    {
        if (data.Length == 0) return string.Empty;

        var builder = new StringBuilder(Math.Min(data.Length, limit) + 4);
        foreach (byte b in data)
        {
            if (builder.Length >= limit) { builder.Append('…'); break; }
            builder.Append(b is >= 0x20 and < 0x7F ? (char)b : b is 0x0A or 0x0D or 0x09 ? ' ' : '.');
        }
        return builder.ToString().Trim();
    }

    private static bool IsBase64Char(char c)
        => c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '+' or '/';

    /// <summary>可读性打分（0–100）：可打印 ASCII 与常见空白字符的占比。</summary>
    private static int ReadableScore(byte[] data)
    {
        if (data.Length == 0) return 0;

        int printable = 0;
        foreach (byte b in data)
        {
            if (b is >= 0x20 and < 0x7F || b is 0x09 or 0x0A or 0x0D) printable++;
        }
        return printable * 100 / data.Length;
    }

    private static byte[]? TryDecode(string text)
    {
        try
        {
            return Convert.FromBase64String(text);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
