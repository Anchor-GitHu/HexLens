using System.IO;
using System.Text;
using HexLens.App.Interop;

namespace HexLens.App.Diagnostics;

/// <summary>
/// 编码功能自检（**不创建任何窗口**，几秒内出结果）。
///
/// 与 <see cref="SmokeTest"/> 的分工：
///   SmokeTest  —— 验证界面与编辑链路，需要真实布局，必须开窗；
///   CodecTest  —— 只验编码库的识别/编解码与跨语言调用（P/Invoke）是否正确，无需 UI。
///
/// 用法：HexLens.App.exe --codec-test=报告路径.txt      退出码 = 失败项数
/// </summary>
public static class CodecTest
{
    /// <summary>执行自检，返回失败项数量。</summary>
    public static int Run(string reportPath)
    {
        var lines = new List<string>();
        int passed = 0;
        int failed = 0;

        void Check(string name, bool ok, string detail = "")
        {
            if (ok)
            {
                passed++;
                lines.Add($"PASS  {name}");
            }
            else
            {
                failed++;
                lines.Add($"FAIL  {name}    {detail}");
            }

            // 每一步都落盘：万一后续步骤卡住，报告里能直接看出停在哪一条
            Write(reportPath, lines);
        }

        lines.Add($"HexLens 编码库自检（无界面）  {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        lines.Add(new string('-', 64));

        // ① 库是否被正确加载（P/Invoke 链路）
        Check("ctfcodec.dll 已加载", CtfCodec.IsAvailable, CtfCodec.UnavailableReason);
        lines.Add($"      版本：{CtfCodec.Version}");

        if (!CtfCodec.IsAvailable)
        {
            lines.Add(new string('-', 64));
            lines.Add($"通过 {passed} 项，失败 {failed} 项");
            Write(reportPath, lines);
            return failed;
        }

        // ② 算法清单
        List<CodecAlgorithm> algorithms = CtfCodec.Algorithms();
        Check("算法清单可读取且数量合理（>100）", algorithms.Count > 100,
            $"实际 {algorithms.Count} 种；诊断：{(string.IsNullOrEmpty(CtfCodec.LastDiagnostic) ? "(无)" : CtfCodec.LastDiagnostic)}");
        lines.Add($"      算法数：{algorithms.Count}（可逆 {algorithms.Count(a => a.Reversible)} 种）");

        // ③ 识别：base64
        List<MagicSuggestion> base64Hits = CtfCodec.Suggest("SGVsbG8sIEhleExlbnMh");
        string base64Top = base64Hits.Count > 0 ? base64Hits[0].Algorithm : "(无)";
        Check("识别经典 base64 文本", base64Hits.Any(s => s.Algorithm.Equals("base64", StringComparison.OrdinalIgnoreCase)),
            $"实际最高分：{base64Top}");
        if (base64Hits.Count > 0)
            lines.Add($"      base64 识别：{base64Hits[0].Algorithm} {base64Hits[0].Score}% —— {base64Hits[0].Reason}");

        // ④ 识别：十六进制
        List<MagicSuggestion> hexHits = CtfCodec.Suggest("48656c6c6f2c204865784c656e7321");
        Check("识别十六进制文本", hexHits.Count > 0, "没有任何建议");
        if (hexHits.Count > 0)
            lines.Add($"      hex 识别：{hexHits[0].Algorithm} {hexHits[0].Score}% —— {hexHits[0].Reason}");

        // ⑤ 识别：URL 编码
        List<MagicSuggestion> urlHits = CtfCodec.Suggest("Hello%2C%20HexLens%21");
        Check("识别 URL 编码文本", urlHits.Count > 0, "没有任何建议");
        if (urlHits.Count > 0)
            lines.Add($"      url 识别：{urlHits[0].Algorithm} {urlHits[0].Score}% —— {urlHits[0].Reason}");

        // ⑥ 解码正确性
        byte[]? decoded = CtfCodec.Decode("base64", Encoding.ASCII.GetBytes("SGVsbG8sIEhleExlbnMh"));
        Check("base64 解码结果正确", decoded is not null && Encoding.ASCII.GetString(decoded) == "Hello, HexLens!",
            decoded is null ? "解码返回 null" : $"实际 \"{Encoding.ASCII.GetString(decoded)}\"");

        // ⑦ 编码 → 解码 往返
        byte[] payload = Encoding.UTF8.GetBytes("flag{codec_roundtrip}");
        byte[]? encoded = CtfCodec.Encode("base64", payload);
        byte[]? roundtrip = encoded is null ? null : CtfCodec.Decode("base64", encoded);
        Check("编码 → 解码往返一致", roundtrip is not null && roundtrip.AsSpan().SequenceEqual(payload),
            roundtrip is null ? "往返返回 null" : "内容不一致");

        // ⑧ 错误处理：不存在的算法名不应崩溃
        byte[]? bad = CtfCodec.Decode("definitely-not-an-algorithm", payload);
        Check("未知算法名返回失败而不是抛异常", bad is null, "居然返回了数据");
        Check("失败时能取到错误说明", !string.IsNullOrWhiteSpace(CtfCodec.LastError), "错误信息为空");

        // ⑨ 端到端：真实样本 → 识别 → 解码 → 结果是 PNG
        string? sample = FindSample("demo_base64_png.txt");
        if (sample is null)
        {
            Check("找到端到端样本 demo_base64_png.txt", false, "在仓库里没找到该样本");
        }
        else
        {
            string text = File.ReadAllText(sample).Trim();
            List<MagicSuggestion> hits = CtfCodec.Suggest(text);
            Check("样本被识别为 base64",
                hits.Any(s => s.Algorithm.Equals("base64", StringComparison.OrdinalIgnoreCase)),
                hits.Count > 0 ? $"最高分是 {hits[0].Algorithm}" : "没有任何建议");

            byte[]? file = CtfCodec.Decode("base64", Encoding.ASCII.GetBytes(text));
            bool isPng = file is { Length: > 8 }
                         && file[0] == 0x89 && file[1] == 0x50 && file[2] == 0x4E && file[3] == 0x47;
            Check("样本解码后是合法 PNG（签名 89 50 4E 47）", isPng,
                file is null ? "解码返回 null" : $"得到 {file.Length} 字节，开头 {Convert.ToHexString(file.AsSpan(0, Math.Min(4, file.Length)))}");
            if (file is not null) lines.Add($"      端到端：base64 文本 → {file.Length:N0} 字节 PNG");
        }

        lines.Add(new string('-', 64));
        lines.Add($"通过 {passed} 项，失败 {failed} 项");

        Write(reportPath, lines);
        return failed;
    }

    private static void Write(string reportPath, List<string> lines)
    {
        string report = string.Join(Environment.NewLine, lines);
        try
        {
            File.WriteAllText(reportPath, report, new UTF8Encoding(true));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"报告写入失败：{ex.Message}");
        }
        Console.WriteLine(report);
    }

    /// <summary>从输出目录向上找仓库里的 samples 目录。</summary>
    private static string? FindSample(string fileName)
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Combine(directory.FullName, "samples", fileName);
            if (File.Exists(candidate)) return candidate;
            directory = directory.Parent;
        }
        return null;
    }
}
