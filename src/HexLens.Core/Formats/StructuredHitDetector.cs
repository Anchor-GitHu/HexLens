namespace HexLens.Core.Formats;

/// <summary>一次"结构化命中"：签名位置 + 长度推导结果。</summary>
public sealed record StructuredHit(SignatureMatch Match, MeasureResult Measure)
{
    /// <summary>命中的签名。</summary>
    public FileSignature Signature => Match.Signature;

    /// <summary>命中偏移。</summary>
    public int Offset => Match.Offset;
}

/// <summary>
/// 结构化命中判定：只在"看起来真的是一个文件"时才认。
///
/// 为什么需要它：像 ICO 的 00 00 01 00、ESE 的 EF CD AB 89 这类短魔数，
/// 在随机或打乱的位流里撞上的概率并不低。位平面扫描与位反转探测如果只看魔数，
/// 一次能报出十几条噪声，把真正的载荷淹掉。这里的判据是：
/// ① 命中位置必须靠近开头（文件都是从自己的第 0 字节开始）；
/// ② 长度必须能被该格式的结构推导出来（有结构 = 大概率不是巧合）。
/// </summary>
public static class StructuredHitDetector
{
    private const Confidence MinimumConfidence = Confidence.Medium;

    /// <summary>
    /// 在候选数据里寻找结构化命中。
    /// </summary>
    /// <param name="data">候选数据（位平面提取结果 / 反转后的缓冲区）。</param>
    /// <param name="maxHeadOffset">允许的命中偏移上限。</param>
    /// <param name="requireMeasurableLength">是否要求长度可推导（探测阶段可放宽以支持大于探测窗口的载荷）。</param>
    /// <param name="maxCandidates">最多检查多少个候选。</param>
    public static StructuredHit? Detect(
        ReadOnlySpan<byte> data,
        int maxHeadOffset = 64,
        bool requireMeasurableLength = true,
        int maxCandidates = 16)
    {
        if (data.Length < 8) return null;

        var candidates = new List<SignatureMatch>();

        SignatureMatch? head = SignatureDatabase.IdentifyAt(data, 0);
        if (head is not null) candidates.Add(head);

        foreach (SignatureMatch match in SignatureDatabase.Scan(data, maxPerSignature: 1))
        {
            if (match.Offset > maxHeadOffset) break;
            candidates.Add(match);
            if (candidates.Count >= maxCandidates) break;
        }

        StructuredHit? best = null;

        foreach (SignatureMatch candidate in candidates)
        {
            if (candidate.Confidence < MinimumConfidence) continue;
            if (candidate.Offset > maxHeadOffset) continue;

            MeasureResult measure = requireMeasurableLength
                ? FormatSizers.Measure(data, candidate.Offset, candidate.Signature)
                : new MeasureResult(0, candidate.Confidence, "探测阶段未做长度推导");

            if (requireMeasurableLength && (measure.Length <= 0 || measure.Confidence < MinimumConfidence))
                continue;

            // 越靠前越可信；同偏移时置信度高者优先
            if (best is null
                || candidate.Offset < best.Offset
                || (candidate.Offset == best.Offset && candidate.Confidence > best.Match.Confidence))
            {
                best = new StructuredHit(candidate, measure);
            }
        }

        return best;
    }
}
