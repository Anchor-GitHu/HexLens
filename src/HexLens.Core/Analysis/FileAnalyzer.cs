using HexLens.Core.Carving;
using HexLens.Core.Clues;
using HexLens.Core.Formats;
using HexLens.Core.Stego;

namespace HexLens.Core.Analysis;

/// <summary>一次完整分析的结论。</summary>
public sealed record AnalysisResult(
    int Length,
    string Md5,
    string Sha1,
    string Sha256,
    string Crc32,
    double OverallEntropy,
    SignatureMatch? Identified,
    CarveReport Carve,
    IReadOnlyList<Clue> Clues,
    IReadOnlyList<LsbHit> LsbHits,
    IReadOnlyList<EntropyBlock> HighEntropyRegions,
    IReadOnlyList<ExtractedString> Strings,
    IReadOnlyList<ExtractedString> SuspiciousStrings,
    int GifFrameCount,
    string? CarrierDescription,
    IReadOnlyList<string> Diagnostics,
    TimeSpan Elapsed)
{
    /// <summary>主文件类型显示名。</summary>
    public string TypeText => Identified is null ? "未知类型" : Identified.Signature.Name;

    /// <summary>线索条数。</summary>
    public int ClueCount => Clues.Count;
}

/// <summary>分析参数。</summary>
public sealed class AnalysisOptions
{
    /// <summary>是否做文件签名扫描（carving）。</summary>
    public bool EnableCarving { get; init; } = true;

    /// <summary>是否做位平面扫描。</summary>
    public bool EnableLsbSweep { get; init; } = true;

    /// <summary>是否提取字符串。</summary>
    public bool EnableStrings { get; init; } = true;

    /// <summary>是否生成线索。</summary>
    public bool EnableClues { get; init; } = true;

    /// <summary>字符串结果上限。</summary>
    public int MaxStrings { get; init; } = 5000;

    /// <summary>位平面扫描参数。</summary>
    public LsbSweepOptions Lsb { get; init; } = new();

    /// <summary>高熵区检测的块大小（比色带粒度大：小块熵值波动大，连续区间判定容易失手）。</summary>
    public int HighEntropyBlockSize { get; init; } = 1024;

    /// <summary>熵色带的块大小。</summary>
    public int EntropyBlockSize { get; init; } = 256;
}

/// <summary>
/// 分析总装：一次调用完成"识别 → 定界 → 解码 → 隐写扫描 → 出线索"。
/// UI 只需要调这一个入口。
/// </summary>
public static class FileAnalyzer
{
    /// <summary>对整份数据做完整分析。</summary>
    public static AnalysisResult Analyze(ReadOnlySpan<byte> data, string? fileName = null, AnalysisOptions? options = null)
    {
        AnalysisOptions opts = options ?? new AnalysisOptions();
        var diagnostics = new List<string>();
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        var digests = ByteStatistics.Digests(data);
        double entropy = EntropyCalculator.Shannon(data);

        SignatureMatch? identified = null;
        try
        {
            identified = SignatureDatabase.IdentifyAt(data, 0);
        }
        catch (Exception ex)
        {
            diagnostics.Add($"类型识别失败：{ex.Message}");
        }

        CarveReport carve = new([], [], data.Length, []);
        if (opts.EnableCarving)
        {
            try
            {
                carve = CarveScanner.Scan(data);
                diagnostics.AddRange(carve.Diagnostics);
            }
            catch (Exception ex)
            {
                diagnostics.Add($"签名扫描失败：{ex.Message}");
            }
        }

        // 载体解码（PNG/BMP/GIF/WAV）——位平面分析必须有真实像素/样本
        string? carrierDescription = null;
        int gifFrameCount = 0;
        ISampleGrid? carrier = null;

        try
        {
            (carrier, carrierDescription, gifFrameCount) = DecodeCarrier(data, 0, identified);
        }
        catch (Exception ex)
        {
            diagnostics.Add($"载体解码失败：{ex.Message}");
        }

        var lsbHits = new List<LsbHit>();
        if (opts.EnableLsbSweep && carrier is not null)
        {
            try
            {
                lsbHits = LsbExtractor.Sweep(carrier, opts.Lsb);
                if (lsbHits.Count == 0)
                    diagnostics.Add($"位平面扫描未发现文件签名（已试 {carrier.Describe}）");
            }
            catch (Exception ex)
            {
                diagnostics.Add($"位平面扫描失败：{ex.Message}");
            }
        }

        var strings = new List<ExtractedString>();
        var suspicious = new List<ExtractedString>();
        if (opts.EnableStrings)
        {
            try
            {
                strings = StringExtractor.Extract(data, maxResults: opts.MaxStrings);
                suspicious = strings.Where(static s => StringExtractor.IsSuspicious(s.Text)).ToList();
            }
            catch (Exception ex)
            {
                diagnostics.Add($"字符串提取失败：{ex.Message}");
            }
        }

        List<EntropyBlock> highEntropy;
        try
        {
            highEntropy = EntropyCalculator.FindHighEntropyRegions(data, opts.HighEntropyBlockSize);
        }
        catch (Exception ex)
        {
            diagnostics.Add($"熵分析失败：{ex.Message}");
            highEntropy = [];
        }

        var clues = new List<Clue>();
        if (opts.EnableClues)
        {
            try
            {
                clues = ClueEngine.Build(data, fileName, identified, carve, lsbHits, strings, highEntropy, gifFrameCount);
            }
            catch (Exception ex)
            {
                diagnostics.Add($"线索生成失败：{ex.Message}");
            }
        }

        stopwatch.Stop();

        return new AnalysisResult(
            data.Length,
            digests.Md5, digests.Sha1, digests.Sha256, digests.Crc32,
            entropy, identified, carve, clues, lsbHits, highEntropy,
            strings, suspicious, gifFrameCount, carrierDescription,
            diagnostics, stopwatch.Elapsed);
    }

    /// <summary>
    /// 按识别出的类型解码载体。
    /// </summary>
    public static (ISampleGrid? Carrier, string? Description, int GifFrameCount) DecodeCarrier(
        ReadOnlySpan<byte> data, int offset, SignatureMatch? identified)
    {
        if (identified is null || offset >= data.Length) return (null, null, 0);

        switch (identified.Signature.Id)
        {
            case "png":
            {
                RasterImage? image = PngDecoder.Decode(data, offset, out string error);
                return image is null ? (null, null, 0) : (image, image.Describe, 0);
            }

            case "bmp":
            {
                RasterImage? image = BmpDecoder.Decode(data, offset, out string error);
                return image is null ? (null, null, 0) : (image, image.Describe, 0);
            }

            case "gif":
            {
                List<GifFrameInfo> frames = GifDecoder.ListFrames(data, offset, out string error);
                List<RasterImage> images = GifDecoder.DecodeFrames(data, offset, 1, out _);
                if (images.Count == 0) return (null, null, frames.Count);
                return (images[0], images[0].Describe + $"（共 {frames.Count} 帧）", frames.Count);
            }

            case "wav":
            {
                AudioSamples? audio = WavReader.Read(data, offset, out string error);
                return audio is null ? (null, null, 0) : (audio, audio.Describe, 0);
            }

            default:
                return (null, null, 0);
        }
    }
}
