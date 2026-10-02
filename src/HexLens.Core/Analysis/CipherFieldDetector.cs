using System.Text;
using HexLens.Core.Formats;

namespace HexLens.Core.Analysis;

/// <summary>一段疑似加密载荷的判定结果。</summary>
/// <param name="Offset">数据在文件中的偏移。</param>
/// <param name="Length">长度。</param>
/// <param name="Entropy">字节熵（bit/字节）。注意小样本的绝对熵天然偏低。</param>
/// <param name="NormalizedEntropy">熵 ÷ 该长度下的可达上限（0–1）。**判据应该看这个**。</param>
/// <param name="BlockHint">块长推测（0 表示没找到规整块长）。</param>
/// <param name="DigestHint">长度是否命中常见摘要/哈希长度。</param>
/// <param name="Family">推测的算法族文本。</param>
/// <param name="Notes">补充依据。</param>
public sealed record CipherField(
    int Offset,
    int Length,
    double Entropy,
    double NormalizedEntropy,
    int BlockHint,
    string? DigestHint,
    string Family,
    IReadOnlyList<string> Notes);

/// <summary>
/// 「疑似加密字段」检测。
///
/// 定位说明：**它不可能认出算法** —— 密文没有头部，任何声称"从字节看出是 AES"的工具都在编。
/// 它真正能给的是一句有用的话：**"这里不是文件碎片，是一段需要密钥的密文，
/// 块长 16 字节 / 或长度像 SHA-256，去别处找密码"**。
///
/// 判据全部是结构性事实，不猜：
///   ① 熵接近 8            —— 数据被打散过
///   ② 没有已知文件头       —— 不是"换了个扩展名的文件"
///   ③ 长度规整             —— 是块长的整数倍，或命中常见摘要长度
///   ④ 长度不大             —— 压缩流会很长，单条密文通常只有几十到几百字节
///
/// 反过来，判据也用于**排除**：JPEG 的压缩数据、ZIP 的 deflate 流同样高熵，
/// 但它们要么很长、要么能靠结构推出来 —— 那些不该报成"加密字段"。
/// </summary>
public static class CipherFieldDetector
{
    /// <summary>
    /// 归一化熵的阈值：实际熵 ÷ 该长度下的可达上限。
    ///
    /// ⚠️ 不能用绝对阈值（比如"熵 &gt; 7.5"）—— 小样本的熵上限受样本量限制：
    ///    48 字节即使**完全随机**，最多也只有 48 个不同字节，熵只有 log2(48) ≈ 5.58。
    ///    用 7.5 去卡会把"短密文"整类漏掉（本项目就在 snake 题上漏过一次）。
    ///
    /// ⚠️ 阈值也不能贴太近：**256 字节随机数据的实测熵约 7.2，归一化只有 ~90%**
    ///    （256 个样本里唯一值通常只有 ~160 个）。所以取 0.85 而不是 0.93 ——
    ///    普通文本的归一化一般在 0.75 以下，分界仍然清楚。
    /// </summary>
    private const double MinNormalizedEntropy = 0.85;

    /// <summary>低于这个熵就不像密文（普通文本约 4–5，压缩/加密接近 8）。</summary>
    private const double MinEntropy = 7.5;

    /// <summary>超过这个长度就不再当"单条密文"看 —— 那更可能是压缩流。</summary>
    private const int MaxCipherLength = 4096;

    /// <summary>太短的片段没有统计意义。</summary>
    private const int MinCipherLength = 16;

    /// <summary>常见摘要/哈希的字节长度。</summary>
    private static readonly Dictionary<int, string> DigestLengths = new()
    {
        [16] = "MD5 / MD2 / MD4（128 bit）",
        [20] = "SHA-1（160 bit）",
        [28] = "SHA-224（224 bit）",
        [32] = "SHA-256 / SHA3-256（256 bit）",
        [48] = "SHA-384（384 bit）",
        [64] = "SHA-512 / SHA3-512（512 bit）",
    };

    /// <summary>
    /// 常见的分组密码块长。**顺序有意义**：16 字节块（AES 系）远比 8 字节块常见，
    /// 而 48 字节这样的长度既能被 8 整除也能被 16 整除 —— 必须先判 16，
    /// 否则会给出"8 字节块 DES"这种误导性结论。
    /// </summary>
    private static readonly (int Block, string Family)[] BlockCipherFamilies =
    [
        (16, "16 字节块：AES / Serpent / Twofish / SM4 / Camellia / ARIA"),
        (8,  "8 字节块：DES / 3DES / Blowfish / CAST5"),
    ];

    /// <summary>
    /// 判定一段数据是否像"加密载荷"。
    /// 不像就返回 null —— 这个检测器的价值在于**不报**，报错了比不报更坏。
    /// </summary>
    public static CipherField? Detect(ReadOnlySpan<byte> data, int offset)
    {
        if (data.Length < MinCipherLength || data.Length > MaxCipherLength) return null;

        // ② 有已知文件头就不是"裸密文"，交给签名识别去管
        if (SignatureDatabase.IdentifyAt(data) is { Offset: 0 }) return null;

        // ① 熵 —— 按该长度下的可达上限归一化（详见 MinNormalizedEntropy 的说明）
        double entropy = EntropyCalculator.Shannon(data);
        double ceiling = Math.Log2(Math.Min(data.Length, 256));
        double normalized = ceiling > 0 ? entropy / ceiling : 0;

        if (normalized < MinNormalizedEntropy) return null;

        var notes = new List<string>
        {
            $"熵 {entropy:F2} bit/字节 = 该长度可达上限的 {normalized:P0}（越接近 100% 越随机）",
            "开头不匹配任何已知文件签名 —— 不是「改了扩展名的普通文件」",
        };

        // ③ 长度指纹
        int blockHint = 0;
        string? blockFamily = null;
        foreach ((int block, string name) in BlockCipherFamilies)
        {
            if (data.Length % block == 0)
            {
                blockHint = block;
                blockFamily = name;
                break;
            }
        }

        string? digest = DigestLengths.GetValueOrDefault(data.Length);

        // 长度既不规整、又不像摘要 —— 那更可能是截断的压缩流，别报
        if (blockHint == 0 && digest is null && !LooksLikePowerOfTwoBlock(data.Length))
        {
            return null;
        }

        // 结论只能有一个，不能上面说摘要、下面说块密码
        string family;
        if (digest is not null && data.Length <= 64)
        {
            family = $"长度 {data.Length} 字节命中常见摘要长度：{digest}"
                   + (blockFamily is not null ? "；也可能是分组密码密文（两者长度会重合）" : "");
        }
        else if (blockFamily is not null)
        {
            family = blockFamily;
            notes.Add($"{data.Length} 字节 = {data.Length / blockHint} 个 {blockHint} 字节块，长度整除块长");
        }
        else
        {
            family = "长度规整，但未命中常见块长/摘要长度";
        }

        return new CipherField(offset, data.Length, entropy, normalized, blockHint, digest, family, notes);
    }

    /// <summary>长度是否是 2 的幂或常见密码学长度（EC 签名、RSA 小块等）。</summary>
    private static bool LooksLikePowerOfTwoBlock(int length)
        => length is 32 or 64 or 96 or 128 or 256 or 512;

    /// <summary>把判定结果写成一句给人看的话。</summary>
    public static string Describe(CipherField field)
    {
        var sb = new StringBuilder();

        // 先给"随机程度"，而不是裸熵 —— 48 字节的绝对熵只有 5.5，
        // 直接写出来会让人以为是"不够随机"，其实它已经是该长度下最随机的样子了。
        sb.Append($"这段 {field.Length} 字节没有文件头，字节分布达到该长度上限的 ")
          .Append($"{field.NormalizedEntropy:P0}")
          .Append($"（熵 {field.Entropy:F2} bit/字节），像是**直接加密出来的数据**，而不是某个文件格式。");

        sb.Append('\n').Append("推测：").Append(field.Family);

        sb.Append("\n\n它能告诉我们：");

        if (field.BlockHint > 0)
        {
            sb.Append($"\n· 长度 {field.Length} 字节是 {field.BlockHint} 字节块长的整数倍")
              .Append("—— 解密需要密钥");
            if (field.BlockHint == 16)
            {
                sb.Append("，且多半还需要一个 IV（CBC/CFB/OFB 要，ECB 不要）");
            }
        }
        else
        {
            sb.Append($"\n· 长度 {field.Length} 字节不符合常见块长 —— 更可能是摘要（不可逆）或流密码");
        }

        sb.Append("\n· 这里**看不到算法**：密文没有头部，任何声称能从字节直接看出 AES/Serpent 的说法都不可信");

        if (field.NormalizedEntropy < 0.99)
        {
            sb.Append($"\n· 归一化熵 {field.NormalizedEntropy:P0} 未满 100%，也可能只是被压缩过的普通内容，"
                    + "先按「压缩/加密」两种可能都试一下");
        }

        sb.Append("\n\nCTF 里这段数据的常见来源：");
        sb.Append("\n· 题目给了密码或提示 → 试分组密码（AES / Serpent / DES…），**ECB 与 CBC 都要试**，");
        sb.Append("\n  密钥的补零/截断/摘要派生方式也要换着试（本项目在 snake 题上就因为密钥大小写与补零方式卡了很久）");
        sb.Append("\n· 没给密码但长度很短 → 先试单字节 XOR 爆破（「编码」页有）");
        sb.Append("\n· 长度恰好像是摘要 → 可能是哈希，该去查表/碰撞，而不是解密");

        return sb.ToString();
    }
}
