using System.Text;
using System.Text.RegularExpressions;
using HexLens.Core.Carving;
using HexLens.Core.Formats;
using HexLens.Core.Util;

namespace HexLens.Core.Stego;

/// <summary>LSB 提取参数。</summary>
/// <param name="BitPlane">取第几位（0 = 最低位）。</param>
/// <param name="Channels">参与提取的通道（null = 全部，按通道号升序）。</param>
/// <param name="MsbFirst">每个字节内的位序：false = 低位先到（最常见），true = 高位先到。</param>
/// <param name="ColumnMajor">扫描顺序：false = 行优先，true = 列优先。</param>
/// <param name="Reverse">是否反转样本访问顺序。</param>
public sealed record LsbOptions(
    int BitPlane = 0,
    int[]? Channels = null,
    bool MsbFirst = false,
    bool ColumnMajor = false,
    bool Reverse = false)
{
    /// <summary>参数的易读描述（界面直接显示）。</summary>
    public string Describe(int channelCount)
    {
        string channels = Channels is null
            ? $"全部 {channelCount} 个通道"
            : string.Join("+", Channels.Select(ChannelLabel));
        string order = ColumnMajor ? "列优先" : "行优先";
        string bits = MsbFirst ? "高位先到" : "低位先到";
        return $"位平面 {BitPlane}｜{channels}｜{order}｜{bits}" + (Reverse ? "｜逆序" : string.Empty);
    }

    private static string ChannelLabel(int index) => index switch
    {
        0 => "R/0",
        1 => "G/1",
        2 => "B/2",
        3 => "A/3",
        _ => index.ToString(),
    };
}

/// <summary>LSB 载荷类型。</summary>
public enum LsbPayloadKind
{
    /// <summary>提取结果是可识别的文件（有文件签名）。</summary>
    File,

    /// <summary>提取结果是可读明文（如 flag{...}）—— CTF 里比藏整文件更常见。</summary>
    Text,
}

/// <summary>一次 LSB 提取的结果（已附带自动识别结论）。</summary>
/// <param name="Options">提取参数。</param>
/// <param name="Payload">提取出的字节流。</param>
/// <param name="Signature">命中的文件签名（文本载荷时为 null）。</param>
/// <param name="MatchOffset">命中位置在提取流内的偏移。</param>
/// <param name="Confidence">置信度。</param>
/// <param name="Score">排序分。</param>
/// <param name="Description">人类可读说明。</param>
/// <param name="Kind">载荷类型。</param>
/// <param name="TextPreview">文本载荷的预览。</param>
public sealed record LsbHit(
    LsbOptions Options,
    byte[] Payload,
    FileSignature? Signature,
    int MatchOffset,
    Confidence Confidence,
    double Score,
    string Description,
    LsbPayloadKind Kind = LsbPayloadKind.File,
    string? TextPreview = null);

/// <summary>LSB 批量试错的参数。</summary>
public sealed class LsbSweepOptions
{
    /// <summary>尝试的位平面数量（从 0 开始，默认 3 个：0/1/2）。</summary>
    public int BitPlanes { get; init; } = 3;

    /// <summary>单次提取的载荷上限。</summary>
    public int MaxPayloadBytes { get; init; } = 64 * 1024 * 1024;

    /// <summary>先用多少字节做快速预判（命中才做全量提取）。</summary>
    public int ProbeBytes { get; init; } = 8192;

    /// <summary>通道组中最多放多少个通道（音频声道多时防止组合爆炸）。</summary>
    public int MaxChannelsPerGroup { get; init; } = 8;

    /// <summary>最多返回多少条命中。</summary>
    public int MaxHits { get; init; } = 12;
}

/// <summary>
/// LSB 提取器：把样本低几位拼成字节流，并立刻做一次签名扫描——
/// "提取 + 识别"闭环是自动发现图片/音频藏匿文件的关键回路。
/// </summary>
public static class LsbExtractor
{
    /// <summary>默认载荷上限。</summary>
    public const int DefaultMaxPayload = 64 * 1024 * 1024;

    /// <summary>低置信度的泛型签名不用于判定 LSB 命中（避免噪声）。</summary>
    private static readonly HashSet<string> NoisySignatures = new(StringComparer.Ordinal)
    {
        "zlib", "mp3-frame", "mpeg-ps", "ese", "lzma", "iso-bmff",
    };

    /// <summary>按给定参数提取位流。</summary>
    public static byte[] Extract(ISampleGrid grid, LsbOptions options, int maxBytes = DefaultMaxPayload)
    {
        if (grid.Count <= 0 || maxBytes <= 0) return [];

        int[] channels = options.Channels is { Length: > 0 }
            ? options.Channels.Where(c => c >= 0 && c < grid.ChannelCount).ToArray()
            : Enumerable.Range(0, grid.ChannelCount).ToArray();
        if (channels.Length == 0) return [];

        int bitPlane = Math.Clamp(options.BitPlane, 0, 7);
        int width = grid.LayoutWidth;
        int height = grid.LayoutHeight;
        int total = grid.Count;

        var writer = new BitWriter(Math.Min(maxBytes, Math.Max(1024, total * channels.Length / 8)));

        for (int n = 0; n < total; n++)
        {
            int index;
            if (options.ColumnMajor && width > 1 && height > 1)
            {
                int x = n / height;
                int y = n % height;
                index = y * width + x;
                if ((uint)index >= (uint)total) index = n;
            }
            else
            {
                index = n;
            }

            if (options.Reverse) index = total - 1 - index;

            foreach (int channel in channels)
            {
                writer.WriteBit((grid.GetSample(index, channel) >> bitPlane) & 1);
            }

            if (writer.ByteCount >= maxBytes)
            {
                byte[] partial = writer.ToArray();
                return partial.Length <= maxBytes ? partial : partial[..maxBytes];
            }
        }

        byte[] result = writer.ToArray();
        if (options.MsbFirst)
        {
            for (int i = 0; i < result.Length; i++) result[i] = ReverseBits(result[i]);
        }
        return result.Length <= maxBytes ? result : result[..maxBytes];
    }

    /// <summary>按给定参数提取并识别（先试文件签名，再试明文）。</summary>
    public static LsbHit? ExtractAndIdentify(ISampleGrid grid, LsbOptions options, int maxBytes = DefaultMaxPayload)
    {
        byte[] payload = Extract(grid, options, maxBytes);
        if (payload.Length < 8) return null;

        StructuredHit? found = StructuredHitDetector.Detect(payload);
        if (found is not null && !NoisySignatures.Contains(found.Signature.Id))
        {
            return new LsbHit(options, payload, found.Signature, found.Offset,
                found.Match.Confidence, Score(options, found.Match.Confidence),
                BuildDescription(grid, options, found.Signature, payload.Length));
        }

        TextPayload? text = DetectTextPayload(payload);
        if (text is null) return null;

        return new LsbHit(options, payload, null, text.Offset, text.Confidence,
            Score(options, text.Confidence) - 5, text.Description, LsbPayloadKind.Text, text.Preview);
    }

    /// <summary>明文载荷判定结果。</summary>
    private sealed record TextPayload(int Offset, string Preview, Confidence Confidence, string Description);

    /// <summary>flag / ctf / key{...} 这类固定形式 —— 命中它基本等于拿到了答案。</summary>
    private static readonly Regex FlagPattern = new(
        @"(?:flag|ctf|key|secret)\{[^}\r\n]{1,200}\}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly string[] TextKeywords = ["flag", "ctf", "secret", "password", "token", "answer"];

    /// <summary>连续可打印长度达到这个值才算明文。</summary>
    /// <remarks>
    /// 20 是个很稳的门槛：随机字节里可打印字符约占 37%，4096 字节里凑出 20 个连续可打印
    /// 的概率约 4096 × 0.37²⁰ ≈ 6e-6，基本不会误报。
    /// 之所以用"最长连续段"而不是"整体可打印比例"：载荷后面通常跟着 0 填充或噪声，
    /// 按整体比例算会被稀释到几个百分点，导致普通明文（无 flag{...} 形式）整个漏掉。
    /// </remarks>
    private const int MinTextRun = 20;

    private static bool IsPrintable(byte b) => b is >= 0x20 and < 0x7F || b is 0x09 or 0x0A or 0x0D;

    /// <summary>找最长的连续可打印段。</summary>
    private static (int Start, int Length) LongestPrintableRun(byte[] data, int limit)
    {
        int n = Math.Min(data.Length, limit);
        int bestStart = 0, bestLength = 0, runStart = 0, runLength = 0;

        for (int i = 0; i < n; i++)
        {
            if (IsPrintable(data[i]))
            {
                if (runLength == 0) runStart = i;
                runLength++;
                if (runLength > bestLength)
                {
                    bestLength = runLength;
                    bestStart = runStart;
                }
            }
            else
            {
                runLength = 0;
            }
        }

        return (bestStart, bestLength);
    }

    /// <summary>快速判断一段位流是否像明文（探测阶段准入用）。</summary>
    private static bool LooksLikeText(byte[] data, int probeLength = 512)
        => LongestPrintableRun(data, probeLength).Length >= MinTextRun;

    /// <summary>
    /// 从位流里找明文载荷。
    ///
    /// 为什么必须有这一支：CTF 里"图片/音频 LSB 直接藏 flag"比藏整个文件常见得多，
    /// 只认文件签名会让这类题完全无声（实测 demo_audio_lsb.wav 就是这样被漏掉的）。
    /// 判定按可信度分三档：固定 flag 形式 &gt; 连续明文含关键词 &gt; 仅"有较长连续明文"。
    /// </summary>
    private static TextPayload? DetectTextPayload(byte[] payload, int scanBytes = 4096)
    {
        int n = Math.Min(payload.Length, scanBytes);
        if (n < 8) return null;

        string text = Encoding.ASCII.GetString(payload, 0, n);

        // ① 最可信：出现 flag{...} / ctf{...} / key{...} 这类固定形式
        Match match = FlagPattern.Match(text);
        if (match.Success)
        {
            return new TextPayload(match.Index, Truncate(match.Value), Confidence.High,
                "位流里直接出现 flag/key 形式的明文");
        }

        // ② 最长连续可打印段
        (int start, int length) = LongestPrintableRun(payload, n);
        if (length < MinTextRun) return null;

        string run = text.Substring(start, length);

        // ③ 段里含常见关键词
        foreach (string keyword in TextKeywords)
        {
            if (run.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                return new TextPayload(start, Truncate(run), Confidence.Medium,
                    $"位流偏移 0x{start:X} 起有 {length} 字节明文，含关键词「{keyword}」");
            }
        }

        // ④ 只有"较长连续明文"这一条证据：报出来，但标低置信度
        return new TextPayload(start, Truncate(run), Confidence.Low,
            $"位流偏移 0x{start:X} 起有 {length} 字节连续可打印内容");
    }

    private static string Truncate(string text) => text.Length > 120 ? text[..120] + "…" : text;

    /// <summary>
    /// 穷举常见参数组合（位平面 × 通道组 × 位序 × 扫描顺序 × 逆序），
    /// 先用少量字节预判、命中后才做全量提取。
    /// </summary>
    public static List<LsbHit> Sweep(ISampleGrid grid, LsbSweepOptions? options = null)
    {
        LsbSweepOptions opts = options ?? new LsbSweepOptions();
        var hits = new List<LsbHit>();
        LsbHit? bestTextHit = null;
        if (grid.Count <= 0) return hits;

        List<int[]> channelGroups = BuildChannelGroups(grid.ChannelCount, opts.MaxChannelsPerGroup);
        bool[] bools = [false, true];

        for (int plane = 0; plane < Math.Max(1, opts.BitPlanes); plane++)
        {
            foreach (int[] group in channelGroups)
            {
                foreach (bool msbFirst in bools)
                {
                    foreach (bool columnMajor in bools)
                    {
                        foreach (bool reverse in bools)
                        {
                            var candidate = new LsbOptions(plane, group, msbFirst, columnMajor, reverse);

                            // 宽进：探测窗口可能小于真实载荷，此时推不出长度，
                            // 只要求"像文件开头"或"像明文"即可进入全量阶段。
                            byte[] probe = Extract(grid, candidate, opts.ProbeBytes);
                            if (probe.Length < 8) continue;
                            bool fileCandidate = StructuredHitDetector.Detect(probe, maxHeadOffset: 2, requireMeasurableLength: false) is not null;
                            if (!fileCandidate && !LooksLikeText(probe)) continue;

                            if (hits.Any(h => h.Options == candidate)) continue;

                            // 严出：全量提取后要求长度能被结构推导，否则视为巧合
                            // （否则 ICO 的 00 00 01 00 之类短魔数会刷出一屏噪声）
                            byte[] payload = Extract(grid, candidate, opts.MaxPayloadBytes);
                            StructuredHit? strict = StructuredHitDetector.Detect(payload);

                            if (strict is null)
                            {
                                // 没有文件签名 —— 再判断位流里是不是明文。
                                // 只认文件签名会漏掉 CTF 里最常见的一类：音频/图片 LSB 直接藏 flag。
                                TextPayload? text = DetectTextPayload(payload);
                                if (text is not null)
                                {
                                    var textHit = new LsbHit(candidate, payload, null, text.Offset,
                                        text.Confidence, Score(candidate, text.Confidence) - 5,
                                        text.Description, LsbPayloadKind.Text, text.Preview);

                                    // 文本命中只保留最好的一条，避免 100 多种组合各报一次
                                    if (bestTextHit is null || textHit.Score > bestTextHit.Score) bestTextHit = textHit;
                                }
                                continue;
                            }

                            if (NoisySignatures.Contains(strict.Signature.Id)) continue;

                            hits.Add(new LsbHit(candidate, payload, strict.Signature, strict.Offset,
                                strict.Match.Confidence, Score(candidate, strict.Match.Confidence),
                                BuildDescription(grid, candidate, strict.Signature, payload.Length)));

                            if (hits.Count >= opts.MaxHits) goto done;
                        }
                    }
                }
            }
        }

    done:
        if (bestTextHit is not null) hits.Add(bestTextHit);
        return hits.OrderByDescending(h => h.Score).ToList();
    }

    private static List<int[]> BuildChannelGroups(int channelCount, int maxPerGroup)
    {
        var groups = new List<int[]>();
        if (channelCount <= 0) return groups;

        int singles = Math.Min(channelCount, maxPerGroup);
        for (int i = 0; i < singles; i++) groups.Add([i]);

        if (channelCount >= 3)
        {
            groups.Add([0, 1, 2]);                        // R,G,B 顺序（最常见）
            if (channelCount >= 4) groups.Add([2, 1, 0]); // B,G,R 顺序
        }
        if (channelCount >= 4) groups.Add(Enumerable.Range(0, channelCount).ToArray());
        else if (channelCount > 1) groups.Add(Enumerable.Range(0, channelCount).ToArray());

        return groups;
    }

    private static double Score(LsbOptions options, Confidence confidence)
    {
        double score = (int)confidence * 100;
        score -= options.BitPlane * 5;                       // 位平面 0 最常见
        score -= (options.Channels?.Length ?? 1) - 1;        // 单通道更常见
        if (!options.MsbFirst) score += 3;
        if (!options.ColumnMajor) score += 2;
        if (options.Reverse) score -= 2;
        return score;
    }

    private static string BuildDescription(ISampleGrid grid, LsbOptions options, FileSignature signature, int payloadLength)
        => $"{grid.Describe} 的 {options.Describe(grid.ChannelCount)} 还原出 {signature.Name}"
           + $"（提取 {payloadLength / 1024.0:F1} KiB）";

    private static byte ReverseBits(byte value)
    {
        value = (byte)((value >> 4) | (value << 4));
        value = (byte)(((value & 0xCC) >> 2) | ((value & 0x33) << 2));
        value = (byte)(((value & 0xAA) >> 1) | ((value & 0x55) << 1));
        return value;
    }
}
