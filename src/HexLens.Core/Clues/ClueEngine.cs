using HexLens.Core.Analysis;
using HexLens.Core.Carving;
using HexLens.Core.Formats;
using HexLens.Core.Stego;

namespace HexLens.Core.Clues;

/// <summary>
/// 线索引擎：把"字节层面的事实"翻译成"可以直接动手的结论"。
/// 它不猜、不编：每条线索都给出偏移、依据与置信度，并附上可执行动作。
/// </summary>
public static class ClueEngine
{
    private static readonly string[] ArchiveIds = ["zip", "rar4", "rar5", "7z"];

    private static readonly Dictionary<string, string[]> ExtensionGroups = new(StringComparer.OrdinalIgnoreCase)
    {
        ["png"] = ["png"],
        ["jpeg"] = ["jpg", "jpeg", "jpe"],
        ["gif"] = ["gif"],
        ["bmp"] = ["bmp", "dib"],
        ["webp"] = ["webp"],
        ["tiff-le"] = ["tif", "tiff"],
        ["tiff-be"] = ["tif", "tiff"],
        ["zip"] = ["zip", "docx", "xlsx", "pptx", "jar", "apk", "epub"],
        ["gzip"] = ["gz", "tgz"],
        ["bzip2"] = ["bz2"],
        ["xz"] = ["xz"],
        ["7z"] = ["7z"],
        ["rar4"] = ["rar"],
        ["rar5"] = ["rar"],
        ["wav"] = ["wav"],
        ["mp3-id3"] = ["mp3"],
        ["flac"] = ["flac"],
        ["ogg"] = ["ogg", "oga", "opus"],
        ["mp4"] = ["mp4", "m4v", "mov"],
        ["pdf"] = ["pdf"],
        ["elf"] = ["elf", "so", "o", "bin"],
        ["pe"] = ["exe", "dll", "sys"],
        ["sqlite"] = ["db", "sqlite", "sqlite3"],
        ["pcap"] = ["pcap"],
        ["pcapng"] = ["pcapng"],
    };

    /// <summary>根据全部分析结果生成线索（按重要性降序）。</summary>
    public static List<Clue> Build(
        ReadOnlySpan<byte> data,
        string? fileName,
        SignatureMatch? identified,
        CarveReport carve,
        IReadOnlyList<LsbHit> lsbHits,
        IReadOnlyList<ExtractedString> strings,
        IReadOnlyList<EntropyBlock> highEntropyRegions,
        int gifFrameCount,
        ClueEngineOptions? options = null)
    {
        ClueEngineOptions opts = options ?? new ClueEngineOptions();
        var clues = new List<Clue>();

        CarvedFile? top = carve.Files.FirstOrDefault(static f => f.Offset == 0);
        int trailingStart = top?.End ?? -1;
        int trailingLength = top is not null ? data.Length - top.End : 0;

        // ① 主文件声明范围之外还有数据——CTF 里最常见的藏匿位置
        if (top is not null && trailingLength > 0)
        {
            clues.Add(new Clue(
                ClueKind.TrailingData,
                $"文件尾部多出 {Size(trailingLength)} 数据",
                $"{top.Signature.Name} 在 0x{top.End:X} 处结束（{top.Note}），但整个文件长 {data.Length} 字节。"
                + "这段数据不在任何已识别结构的声明范围内，优先提取看看。",
                Confidence.High, top.End, trailingLength, 95,
                [
                    new ClueAction("导出这段数据", ClueActionKind.ExtractRange, top.End, trailingLength, "trailing.bin"),
                    new ClueAction("在十六进制中查看", ClueActionKind.RevealInHex, top.End, trailingLength),
                ]));
        }

        // ①-b 尾部这段数据是不是"加密载荷"
        //
        //   光说"多出 394 字节"帮助有限；如果它没有文件头、熵接近 8、长度还规整，
        //   那基本就是一段直接加密出来的密文 —— 这时该提示的是「去别处找密码」，
        //   而不是让人对着十六进制干瞪眼。
        if (top is not null && trailingLength > 0)
        {
            AddCipherFieldClue(clues, data.Slice(top.End, trailingLength), top.End);
        }

        // ①-c 整份文件本身就是一段裸密文（题目直接甩一个 cipher 出来的情况）
        //
        //   ⚠️ 不能只在 top is null 时判：短随机数据很容易被签名库"误认"成某种格式，
        //      那样 top 不为 null、而 trailingLength 又是 0，①-b / ①-c 两个分支都不走，
        //      整类场景会被静默漏掉（本项目就踩过一次）。
        if (top is null || trailingLength == 0)
        {
            AddCipherFieldClue(clues, data, 0);
        }

        // ② 内嵌的完整文件
        foreach (CarvedFile file in carve.Files)
        {
            if (!file.IsEmbedded || file.IsNested) continue;
            if (file.Confidence < Confidence.Medium) continue;

            bool inTrailing = trailingStart >= 0 && file.Offset >= trailingStart;
            string position = inTrailing
                ? "位于主文件声明范围之外"
                : "位于主文件声明范围之内（可能是容器内部内容）";

            clues.Add(new Clue(
                ClueKind.EmbeddedFile,
                $"0x{file.Offset:X} 处发现 {file.Signature.Name}",
                $"{file.RangeText}，{file.SizeText}。{file.Note}；{position}。",
                file.Confidence, file.Offset, file.Length, inTrailing ? 93 : 82,
                [
                    new ClueAction("导出这个文件", ClueActionKind.ExtractRange, file.Offset, file.Length,
                        $"carved_{file.Offset:X}.{file.Signature.Extensions.FirstOrDefault() ?? "bin"}"),
                    new ClueAction("在十六进制中查看", ClueActionKind.RevealInHex, file.Offset, file.Length),
                    new ClueAction("查看结构", ClueActionKind.ShowStructure, file.Offset, file.Length),
                ]));
        }

        // ③ 位平面里还原出的内容（文件或明文）
        int lsbRank = 0;
        foreach (LsbHit hit in lsbHits)
        {
            bool isText = hit.Kind == LsbPayloadKind.Text;

            clues.Add(new Clue(
                ClueKind.LsbPayload,
                isText ? "位平面里藏有明文" : $"位平面里还原出 {hit.Signature?.Name ?? "文件"}",
                isText
                    ? $"{hit.Description}｜预览：{hit.TextPreview}。"
                      + "这类题通常直接把 flag 写进位平面，可在隐写面板切换参数继续枚举完整内容。"
                    : $"{hit.Description}。命中签名位于提取流偏移 0x{hit.MatchOffset:X}，置信度 {hit.Confidence}。"
                      + "注意：位平面提取的「通道顺序/位序」若换个组合可能还原出别的载荷，可在隐写面板继续枚举。",
                hit.Confidence, 0, data.Length, 88 - lsbRank++,
                [
                    new ClueAction("导出还原出的文件", ClueActionKind.ExtractRange, 0, hit.Payload.Length, "lsb_payload.bin"),
                    new ClueAction("查看载体结构", ClueActionKind.ShowStructure, 0, data.Length),
                ]));
            if (lsbRank >= 5) break;
        }

        // ④ 文本里出现 flag/secret 之类关键词
        var seenText = new HashSet<string>(StringComparer.Ordinal);
        int textRank = 0;
        foreach (ExtractedString s in strings)
        {
            if (!StringExtractor.IsSuspicious(s.Text)) continue;
            if (!seenText.Add(s.Text)) continue;

            clues.Add(new Clue(
                ClueKind.SuspiciousText,
                $"0x{s.Offset:X} 处的字符串含关键标记",
                $"[{s.Kind}] {Truncate(s.Text, 200)}",
                Confidence.Medium, s.Offset, s.ByteLength, 70 - textRank++,
                [new ClueAction("在十六进制中查看", ClueActionKind.RevealInHex, s.Offset, s.ByteLength)]));
            if (textRank >= 8) break;
        }

        // ⑤ Base64 数据块（解码后若是文件，或只是可读文本，价值都很高）
        int base64Rank = 0;
        foreach (ExtractedString s in strings)
        {
            if (s.Text.Length < opts.MinBase64Length) continue;

            // 关键：**尝试 0–3 四种起始偏移**。
            // 实战里 Base64 常带前缀（key / data: / flag= …），整串当 Base64 会因长度错位
            // 而解码失败；只试偏移 0 就会把整段漏掉 —— snake.jpg 里的
            // "keyV2hhdCBpcyBOaWNraSBNaW5haidz…" 正是被这一点漏掉的。
            Base64Probe.Result? payload = Base64Probe.Find(s.Text);
            if (payload is null) continue;

            byte[] decoded = payload.Bytes;
            SignatureMatch? inner = SignatureDatabase.IdentifyAt(decoded, 0)
                ?? SignatureDatabase.Scan(decoded, maxPerSignature: 1).FirstOrDefault();

            string prefixNote = payload.Skipped > 0
                ? $"（前缀「{s.Text[..payload.Skipped]}」之后才是 Base64）"
                : string.Empty;

            if (inner is not null && inner.Confidence >= Confidence.Medium)
            {
                clues.Add(new Clue(
                    ClueKind.Base64Blob,
                    $"0x{s.Offset:X} 处的 Base64 解码后是 {inner.Signature.Name}",
                    $"文本长度 {s.Text.Length} 字符{prefixNote}，解码得到 {decoded.Length} 字节，开头即 {inner.Signature.Name} 签名。",
                    Confidence.High, s.Offset, s.ByteLength, 90 - base64Rank++,
                    [
                        new ClueAction("解码并导出", ClueActionKind.DecodeBase64, s.Offset, s.ByteLength,
                            $"decoded_{s.Offset:X}.{inner.Signature.Extensions.FirstOrDefault() ?? "bin"}"),
                        new ClueAction("在十六进制中查看", ClueActionKind.RevealInHex, s.Offset, s.ByteLength),
                    ]));
            }
            else if (payload.IsReadableText)
            {
                clues.Add(new Clue(
                    ClueKind.Base64Blob,
                    $"0x{s.Offset:X} 处的 Base64 解出可读文本",
                    $"文本长度 {s.Text.Length} 字符{prefixNote}，解码得到 {decoded.Length} 字节："
                    + $"「{Base64Probe.Preview(decoded)}」",
                    Confidence.Medium, s.Offset, s.ByteLength, 70 - base64Rank++,
                    [
                        new ClueAction("解码并导出", ClueActionKind.DecodeBase64, s.Offset, s.ByteLength,
                            $"decoded_{s.Offset:X}.txt"),
                        new ClueAction("在十六进制中查看", ClueActionKind.RevealInHex, s.Offset, s.ByteLength),
                    ]));
            }
            else
            {
                clues.Add(new Clue(
                    ClueKind.Base64Blob,
                    $"0x{s.Offset:X} 处有疑似 Base64 数据块",
                    $"长度 {s.Text.Length} 字符{prefixNote}，解码得到 {decoded.Length} 字节，"
                    + "但既不是已知文件，也不是可读文本。",
                    Confidence.Low, s.Offset, s.ByteLength, 45 - base64Rank++,
                    [new ClueAction("在十六进制中查看", ClueActionKind.RevealInHex, s.Offset, s.ByteLength)]));
            }
            if (base64Rank >= 6) break;
        }

        // ⑥ 加密归档：CTF 里的常客（ZipCrypto 已知明文攻击 / 伪加密）
        foreach (CarvedFile file in carve.Files)
        {
            if (!ArchiveIds.Contains(file.Signature.Id) || file.Structure is null) continue;
            if (!file.Structure.Any(static n => n.Detail?.Contains("已加密", StringComparison.Ordinal) == true)) continue;

            clues.Add(new Clue(
                ClueKind.EncryptedArchive,
                "归档中存在加密条目",
                $"{file.RangeText} 的 {file.Signature.Name} 含加密标志。若为 ZipCrypto，可用已知明文攻击（bkcrack）恢复密钥；"
                + "也要留意「伪加密」（本地头与中央目录的加密标志不一致）。",
                Confidence.Medium, file.Offset, file.Length, 80,
                [
                    new ClueAction("导出归档", ClueActionKind.ExtractRange, file.Offset, file.Length, "encrypted.zip"),
                    new ClueAction("查看结构", ClueActionKind.ShowStructure, file.Offset, file.Length),
                ]));
        }

        // ⑦ 多帧动图
        if (gifFrameCount > 1)
        {
            clues.Add(new Clue(
                ClueKind.MultiFrame,
                $"动图共 {gifFrameCount} 帧",
                "多帧 GIF 常被逐帧藏数据（每帧 LSB、帧间差分、帧延迟编码）。"
                + "可在隐写面板逐帧查看位平面。",
                Confidence.Medium, 0, data.Length, 60,
                [new ClueAction("查看结构", ClueActionKind.ShowStructure, 0, data.Length)]));
        }

        // ⑧ 高熵区间（压缩/加密载荷）
        int entropyRank = 0;
        foreach (EntropyBlock region in highEntropyRegions)
        {
            clues.Add(new Clue(
                ClueKind.HighEntropyRegion,
                $"0x{region.Offset:X} 起 {Size(region.Length)} 为高熵数据",
                $"平均熵 {region.Entropy:F2} bit/字节（接近 8 说明接近随机，典型为压缩流或加密数据）。",
                Confidence.Low, region.Offset, region.Length, 50 - entropyRank++,
                [new ClueAction("在十六进制中查看", ClueActionKind.RevealInHex, region.Offset, region.Length)]));
            if (entropyRank >= 4) break;
        }

        // ⑨ 结构异常（CRC 不符、块链中断）
        if (top is not null && top.Structure is not null)
        {
            string[] anomalies = top.Structure
                .Where(static n => n.Detail is not null
                    && (n.Detail.Contains("CRC 不符", StringComparison.Ordinal)
                        || n.Detail.Contains("校验不符", StringComparison.Ordinal)))
                .Select(static n => $"{n.Name} @ 0x{n.Offset:X}")
                .Take(5)
                .ToArray();

            if (anomalies.Length > 0)
            {
                clues.Add(new Clue(
                    ClueKind.StructureAnomaly,
                    "结构校验值不匹配",
                    "以下节点校验失败，说明数据被改动过或是拼接产物：" + string.Join("；", anomalies),
                    Confidence.Medium, 0, data.Length, 55,
                    [new ClueAction("查看结构", ClueActionKind.ShowStructure, 0, data.Length)]));
            }

            if (top.Note.Contains("中断", StringComparison.Ordinal) || top.Note.Contains("截断", StringComparison.Ordinal))
            {
                clues.Add(new Clue(
                    ClueKind.StructureAnomaly,
                    "主文件结构未正常结束",
                    top.Note,
                    Confidence.Low, 0, data.Length, 42,
                    [new ClueAction("查看结构", ClueActionKind.ShowStructure, 0, data.Length)]));
            }
        }

        // ⑩ 扩展名与实际类型不符
        if (identified is not null && ExtensionGroups.TryGetValue(identified.Signature.Id, out string[]? expected))
        {
            string? actualExtension = Path.GetExtension(fileName ?? string.Empty).TrimStart('.').ToLowerInvariant();
            if (actualExtension.Length > 0 && !expected.Contains(actualExtension, StringComparer.OrdinalIgnoreCase))
            {
                clues.Add(new Clue(
                    ClueKind.TypeMismatch,
                    $"扩展名 .{actualExtension} 与实际类型不符",
                    $"文件内容识别为 {identified.Signature.Name}"
                    + $"（期望扩展名 {string.Join("/", expected.Select(e => "." + e))}）。"
                    + "有些题会靠改扩展名误导，也可能整份文件被「套壳」。",
                    Confidence.Medium, 0, data.Length, 65,
                    [new ClueAction("在十六进制中查看", ClueActionKind.RevealInHex, 0, Math.Min(data.Length, 64))]));
            }
        }

        // ⑩-b 扩展名暗示的类型与**文件头**对不上（如 .png 但开头不是 PNG 签名）
        //
        //   这段和 ⑩ 是互补的，别混：
        //     ⑩   = 认得出内容、但扩展名骗人 → 改**扩展名**就完事
        //     ⑩-b = 扩展名说是什么、但文件头不像 → 要改**文件头**才能救
        //
        //   （早期我把「改文件头」的动作塞进了 ⑩，那里内容既然识别成功，
        //     文件头必然与签名相符，条件永远不成立 —— 等于写了一段死代码。
        //     是端到端测试把这个问题暴露出来的。）
        string? extForHeader = Path.GetExtension(fileName ?? string.Empty).TrimStart('.').ToLowerInvariant();
        if (extForHeader.Length > 0 && SignatureDatabase.GetByExtension(extForHeader) is { } byExtension)
        {
            byte[]? standardMagic = byExtension.Anchors.Count > 0 ? byExtension.Anchors[0].Pattern : null;

            if (standardMagic is { Length: > 0 }
                && standardMagic.Length <= data.Length
                && !data[..standardMagic.Length].SequenceEqual(standardMagic))
            {
                byte[] actualMagic = data[..standardMagic.Length].ToArray();

                clues.Add(new Clue(
                    ClueKind.TypeMismatch,
                    $".{extForHeader} 的文件头不是 {byExtension.Name} 的签名",
                    $"扩展名是 .{extForHeader}（通常是 {byExtension.Name}），"
                    + $"但开头 {standardMagic.Length} 字节与标准签名不符。\n"
                    + $"标准：{Convert.ToHexString(standardMagic)}\n"
                    + $"实际：{Convert.ToHexString(actualMagic)}\n"
                    + (identified is null
                        ? "内容也没能识别成任何已知格式 —— 文件头很可能被故意改掉了。"
                        : $"内容目前识别为 {identified.Signature.Name}，也可能是改头套壳。"),
                    Confidence.Medium, 0, data.Length, 68,
                    [
                        new ClueAction("在十六进制中查看", ClueActionKind.RevealInHex, 0, Math.Min(data.Length, 64)),
                        new ClueAction(
                            $"改为 {byExtension.Name} 的文件头",
                            ClueActionKind.WritePayload,
                            0,
                            standardMagic.Length,
                            Convert.ToHexString(standardMagic),
                            standardMagic),
                    ]));
            }
        }

        // ⑩-c PNG 块 CRC 校验
        //
        //   这是"改完能验证"最典型的一处：PNG 手改一个像素/宽高，CRC 立刻对不上，
        //   而多数查看器遇到 CRC 错**直接拒开**，看起来像"文件坏了"。
        //   其实只要把 4 字节 CRC 按当前内容重算写回就行。
        if (PngCrcChecker.LooksLikePng(data))
        {
            List<CrcMismatch> crcBad = PngCrcChecker.Check(data);

            if (crcBad.Count > 0)
            {
                var crcActions = new List<ClueAction>
                {
                    new("在十六进制中查看", ClueActionKind.RevealInHex, crcBad[0].Offset, crcBad[0].Length),
                };

                // 每个坏块给一个"重算并写回"动作；上限 8 个，避免坏块多时按钮刷屏
                foreach (CrcMismatch mismatch in crcBad.Take(8))
                {
                    crcActions.Add(new ClueAction(
                        $"修正 {mismatch.Name} 的 CRC",
                        ClueActionKind.WritePayload,
                        mismatch.Offset,
                        mismatch.Length,
                        null,
                        mismatch.Payload));
                }

                string crcDetail = string.Join("\n", crcBad.Take(6).Select(static m => "· " + m.DetailText));
                if (crcBad.Count > 6) crcDetail += $"\n…另有 {crcBad.Count - 6} 个块同样不符";

                crcDetail += "\n\n块数据被改动过（改宽高、像素、调色板都会这样）。"
                           + "多数查看器遇到 CRC 错会直接拒开，把 CRC 按当前内容重算写回即可修复。";

                clues.Add(new Clue(
                    ClueKind.StructureAnomaly,
                    $"PNG 有 {crcBad.Count} 个块的 CRC 不符",
                    crcDetail,
                    Confidence.High,
                    crcBad[0].Offset,
                    crcBad[0].Length,
                    72,
                    crcActions));
            }
        }

        // ⑪ 位反转 / 字节反转探测
        if (opts.EnableReversalProbe && data.Length > 16 && data.Length <= opts.ReversalProbeLimit)
        {
            clues.AddRange(ProbeReversals(data));
        }

        return clues
            .OrderByDescending(static c => c.Priority)
            .ThenBy(static c => c.Offset)
            .Take(opts.MaxClues)
            .ToList();
    }

    /// <summary>位反转与字节反转探测（CTF 常见的"数据被翻转"变体）。</summary>
    private static List<Clue> ProbeReversals(ReadOnlySpan<byte> data)
    {
        var result = new List<Clue>();

        byte[] reversedBits = new byte[data.Length];
        for (int i = 0; i < data.Length; i++) reversedBits[i] = ReverseBits(data[i]);

        SignatureMatch? bitHit = FindStructuredHit(reversedBits);
        if (bitHit is not null)
        {
            result.Add(new Clue(
                ClueKind.ReversedData,
                "每个字节位序被反转",
                $"把每个字节的 8 个位倒过来之后，开头出现 {bitHit.Signature.Name} 签名，且长度可推导。"
                + "这是常见的「位反转」混淆，反转后即可正常解析。",
                Confidence.High, 0, data.Length, 92,
                [new ClueAction("在十六进制中查看", ClueActionKind.RevealInHex, 0, Math.Min(data.Length, 64))]));
        }

        byte[] reversedBytes = data.ToArray();
        Array.Reverse(reversedBytes);
        SignatureMatch? byteHit = FindStructuredHit(reversedBytes);
        if (byteHit is not null)
        {
            result.Add(new Clue(
                ClueKind.ReversedData,
                "整个文件字节序被倒置",
                $"把字节顺序整体颠倒后，开头出现 {byteHit.Signature.Name} 签名，且长度可推导。",
                Confidence.High, 0, data.Length, 91,
                [new ClueAction("在十六进制中查看", ClueActionKind.RevealInHex, 0, Math.Min(data.Length, 64))]));
        }

        return result;
    }

    /// <summary>
    /// 在翻转后的数据里找"真的像文件"的证据。
    /// 只看魔数会大量误报（PNG 位反转后常在随机字节里撞上 ICO 的 00 00 01 00），
    /// 判据与位平面扫描共用：命中必须靠近开头且长度可推导。
    /// </summary>
    private static SignatureMatch? FindStructuredHit(byte[] candidate)
    {
        StructuredHit? hit = StructuredHitDetector.Detect(candidate, maxHeadOffset: 16);
        return hit?.Match;
    }

    private static byte[]? TryDecodeBase64(string text)
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

    private static byte ReverseBits(byte value)
    {
        value = (byte)((value >> 4) | (value << 4));
        value = (byte)(((value & 0xCC) >> 2) | ((value & 0x33) << 2));
        value = (byte)(((value & 0xAA) >> 1) | ((value & 0x55) << 1));
        return value;
    }

    /// <summary>
    /// 把「疑似加密字段」的判定结果变成一条线索。
    ///
    /// 这个检测器的价值全在**不报**上：JPEG 压缩数据、ZIP deflate 流、任何压缩过的内容
    /// 都是高熵的，误报会立刻把线索列表变成噪声。所以判据额外要求
    /// 「长度不大 + 没有文件头 + 长度规整」，宁可漏报。
    /// </summary>
    private static void AddCipherFieldClue(List<Clue> clues, ReadOnlySpan<byte> segment, int offset)
    {
        if (CipherFieldDetector.Detect(segment, offset) is not { } field) return;

        clues.Add(new Clue(
            ClueKind.SuspectedCipher,
            $"0x{offset:X} 处像是加密数据（{field.Length} 字节，随机度 {field.NormalizedEntropy:P0}）",
            CipherFieldDetector.Describe(field),
            Confidence.Medium,
            offset,
            field.Length,
            70,
            [
                new ClueAction("导出这段数据", ClueActionKind.ExtractRange, offset, field.Length, "cipher.bin"),
                new ClueAction("在十六进制中查看", ClueActionKind.RevealInHex, offset, field.Length),
            ]));
    }

    private static string Size(int length) => length switch
    {
        < 1024 => $"{length} B",
        < 1024 * 1024 => $"{length / 1024.0:F1} KiB",
        _ => $"{length / 1048576.0:F2} MiB",
    };

    private static string Truncate(string text, int max) => text.Length <= max ? text : text[..max] + "…";
}
