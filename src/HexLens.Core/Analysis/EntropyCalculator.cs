namespace HexLens.Core.Analysis;

/// <summary>一段连续区间的熵（用于十六进制视图上方的熵色带）。</summary>
public sealed record EntropyBlock(int Offset, int Length, double Entropy)
{
    /// <summary>
    /// 是否属于"高熵"（压缩/加密数据的典型特征）。
    /// 阈值取 7.0：压缩数据块通常 7.5 以上，文本约 4–5，7.0 是安全分界。
    /// 注意 256 字节小块的熵本身在 7.28 附近波动（样本量越小方差越大），
    /// 判定连续区间时应使用更大的块（见 <see cref="EntropyCalculator.FindHighEntropyRegions"/> 的 blockSize）。
    /// </summary>
    public bool IsHighEntropy => Entropy >= 7.0;

    /// <summary>是否属于"低熵"（纯 0 填充、重复模式）。</summary>
    public bool IsLowEntropy => Entropy <= 0.5;
}

/// <summary>香农熵与熵剖面计算。</summary>
public static class EntropyCalculator
{
    /// <summary>一段数据的香农熵（0..8 bit/字节）。</summary>
    public static double Shannon(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0;

        Span<int> counts = stackalloc int[256];
        counts.Clear();
        foreach (byte b in data) counts[b]++;

        double entropy = 0;
        double total = data.Length;
        foreach (int count in counts)
        {
            if (count == 0) continue;
            double p = count / total;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    /// <summary>
    /// 按固定块大小生成熵剖面。
    /// </summary>
    /// <param name="data">缓冲区。</param>
    /// <param name="blockSize">块大小（字节）。</param>
    /// <param name="maxBlocks">最大块数（超出则自动放大块大小，避免 UI 数据量爆炸）。</param>
    public static List<EntropyBlock> Profile(ReadOnlySpan<byte> data, int blockSize = 256, int maxBlocks = 4096)
    {
        var blocks = new List<EntropyBlock>();
        if (data.Length == 0) return blocks;

        int size = Math.Max(16, blockSize);
        while (data.Length / size > maxBlocks) size *= 2;

        for (int offset = 0; offset < data.Length; offset += size)
        {
            int length = Math.Min(size, data.Length - offset);
            blocks.Add(new EntropyBlock(offset, length, Shannon(data.Slice(offset, length))));
        }
        return blocks;
    }

    /// <summary>
    /// 找出高熵连续区间（可能藏着压缩/加密数据）。
    /// blockSize 默认 1024：256 字节的小块熵值波动太大（随机数据均值仅约 7.28），
    /// 会让"连续 N 块都高熵"的判定频繁失手；1024 字节块的均值约 7.6，判定稳定。
    /// </summary>
    public static List<EntropyBlock> FindHighEntropyRegions(
        ReadOnlySpan<byte> data,
        int blockSize = 1024,
        int minRunBlocks = 4)
    {
        var result = new List<EntropyBlock>();
        List<EntropyBlock> profile = Profile(data, blockSize);
        int runStart = -1;
        int runBlocks = 0;
        double sum = 0;

        for (int i = 0; i <= profile.Count; i++)
        {
            bool high = i < profile.Count && profile[i].IsHighEntropy;
            if (high)
            {
                if (runStart < 0) { runStart = i; runBlocks = 0; sum = 0; }
                runBlocks++;
                sum += profile[i].Entropy;
            }
            else if (runStart >= 0)
            {
                if (runBlocks >= minRunBlocks)
                {
                    EntropyBlock first = profile[runStart];
                    EntropyBlock last = profile[i - 1];
                    result.Add(new EntropyBlock(first.Offset, last.Offset + last.Length - first.Offset, sum / runBlocks));
                }
                runStart = -1;
            }
        }
        return result;
    }
}
