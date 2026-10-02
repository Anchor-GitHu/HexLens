using HexLens.Core.Formats;

namespace HexLens.Core.Carving;

/// <summary>一个被识别出来的文件（可能是主文件，也可能是藏在里面的）。</summary>
public sealed record CarvedFile(
    int Offset,
    int Length,
    FileSignature Signature,
    Confidence Confidence,
    string Note,
    IReadOnlyList<StructureNode>? Structure,
    int NestingDepth,
    int Index)
{
    /// <summary>结束偏移（不含）。</summary>
    public int End => Offset + Length;

    /// <summary>是否不是从 0 开始（可能被附加在别的数据后面）。</summary>
    public bool IsEmbedded => Offset > 0;

    /// <summary>是否位于另一个已识别文件内部（通常属于正常内容，而非藏匿）。</summary>
    public bool IsNested => NestingDepth > 0;

    /// <summary>区间文本。</summary>
    public string RangeText => $"0x{Offset:X} – 0x{End:X}";

    /// <summary>大小文本。</summary>
    public string SizeText => Length switch
    {
        < 1024 => $"{Length} B",
        < 1024 * 1024 => $"{Length / 1024.0:F1} KiB",
        _ => $"{Length / 1048576.0:F2} MiB",
    };
}

/// <summary>一次完整的扫描报告。</summary>
public sealed record CarveReport(
    IReadOnlyList<CarvedFile> Files,
    IReadOnlyList<SignatureMatch> RawMatches,
    int DataLength,
    IReadOnlyList<string> Diagnostics)
{
    /// <summary>按"最可能是藏匿载荷"排序：非嵌套、非零偏移的优先。</summary>
    public IEnumerable<CarvedFile> SuspiciousFirst =>
        Files.OrderByDescending(f => f.IsEmbedded && !f.IsNested)
             .ThenByDescending(f => f.Confidence)
             .ThenBy(f => f.Offset);
}

/// <summary>扫描参数。</summary>
public sealed class CarveOptions
{
    /// <summary>同一签名最多保留的命中数（防止 zlib 之类噪声签名刷屏）。</summary>
    public int MaxPerSignature { get; init; } = 64;

    /// <summary>最多识别多少个文件。</summary>
    public int MaxFiles { get; init; } = 512;
}

/// <summary>
/// Carving 扫描器：在任意字节流里定位所有已知文件头，为每个命中推导长度，
/// 并判断它是"正常嵌套"还是"外部附加/藏匿"。
/// </summary>
public static class CarveScanner
{
    /// <summary>
    /// 泛型占位签名（同偏移命中时，具体签名优先于它们）。
    /// </summary>
    private static readonly HashSet<string> GenericSignatures = new(StringComparer.Ordinal)
    {
        "iso-bmff", "zlib", "mp3-frame", "mpeg-ps", "ese", "lzma",
    };

    /// <summary>执行扫描。</summary>
    public static CarveReport Scan(ReadOnlySpan<byte> data, CarveOptions? options = null)
    {
        CarveOptions opts = options ?? new CarveOptions();
        var diagnostics = new List<string>();

        if (data.Length == 0)
            return new CarveReport([], [], 0, ["缓冲区为空"]);

        List<SignatureMatch> raw = SignatureDatabase.Scan(data, maxPerSignature: opts.MaxPerSignature);

        // 同一起点可能被多个签名命中（CAFEBABE、ftyp 家族、zlib 噪声）：只留最可信的一个
        var best = new Dictionary<int, SignatureMatch>();
        foreach (SignatureMatch m in raw)
        {
            if (!best.TryGetValue(m.Offset, out SignatureMatch? current) || Prefer(m, current))
                best[m.Offset] = m;
        }

        var ordered = best.Values.OrderBy(m => m.Offset).ToList();
        var files = new List<CarvedFile>();

        foreach (SignatureMatch m in ordered)
        {
            if (files.Count >= opts.MaxFiles)
            {
                diagnostics.Add($"命中数超过 {opts.MaxFiles}，已截断（可提高上限或先切片分析）");
                break;
            }

            MeasureResult measure = FormatSizers.Measure(data, m.Offset, m.Signature, raw);
            int length = measure.Length;

            if (length <= 0)
            {
                int next = FindNextOffset(ordered, m.Offset);
                length = (next > m.Offset ? next : data.Length) - m.Offset;
                measure = new MeasureResult(length, Confidence.Low, "长度未知，按下一个签名/末尾估算", measure.Structure);
            }

            length = Math.Clamp(length, 1, data.Length - m.Offset);
            files.Add(new CarvedFile(m.Offset, length, m.Signature, measure.Confidence, measure.Note,
                measure.Structure, 0, files.Count));
        }

        // 嵌套深度：被多少个大区间包住（用于区分"容器内部正常内容"与"外部藏匿"）
        var measured = new List<CarvedFile>(files.Count);
        for (int i = 0; i < files.Count; i++)
        {
            CarvedFile f = files[i];
            int depth = 0;
            for (int j = 0; j < files.Count; j++)
            {
                if (i == j) continue;
                CarvedFile other = files[j];
                if (other.Length <= f.Length) continue;
                if (other.Offset <= f.Offset && other.End >= f.End) depth++;
            }
            measured.Add(f with { NestingDepth = depth });
        }

        if (measured.Count == 0)
            diagnostics.Add("未识别出任何已知文件头（可能是纯文本、自定义格式或已加密）");

        return new CarveReport(measured, raw, data.Length, diagnostics);
    }

    private static bool Prefer(SignatureMatch candidate, SignatureMatch current)
    {
        if (candidate.Confidence != current.Confidence)
            return candidate.Confidence > current.Confidence;

        bool candidateGeneric = GenericSignatures.Contains(candidate.Signature.Id);
        bool currentGeneric = GenericSignatures.Contains(current.Signature.Id);
        if (candidateGeneric != currentGeneric)
            return !candidateGeneric;

        return false;
    }

    private static int FindNextOffset(List<SignatureMatch> ordered, int offset)
    {
        foreach (SignatureMatch m in ordered)
        {
            if (m.Offset > offset) return m.Offset;
        }
        return -1;
    }
}
