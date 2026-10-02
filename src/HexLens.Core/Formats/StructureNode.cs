namespace HexLens.Core.Formats;

/// <summary>
/// 结构树节点：把容器格式（PNG 块、ZIP 条目、RIFF 子块、MP4 盒子……）摊开给用户看。
/// 与长度推导共用同一套解析代码，避免"能认出来但说不清边界"。
/// </summary>
/// <param name="Name">节点名（如 IHDR、fmt、central directory）。</param>
/// <param name="Offset">相对整个缓冲区的起始偏移。</param>
/// <param name="Length">节点覆盖的字节数。</param>
/// <param name="Detail">人类可读的字段摘要。</param>
/// <param name="Children">子节点。</param>
public sealed record StructureNode(
    string Name,
    int Offset,
    int Length,
    string? Detail = null,
    IReadOnlyList<StructureNode>? Children = null)
{
    /// <summary>偏移的十六进制显示（8 位，带 0x 前缀）。</summary>
    public string OffsetText => $"0x{Offset:X8}";

    /// <summary>长度的易读显示。</summary>
    public string LengthText => Length switch
    {
        < 1024 => $"{Length} B",
        < 1024 * 1024 => $"{Length / 1024.0:F1} KiB",
        _ => $"{Length / 1048576.0:F2} MiB",
    };

    /// <summary>递归统计节点总数。</summary>
    public int Count()
    {
        int n = 1;
        if (Children is not null)
            foreach (StructureNode c in Children) n += c.Count();
        return n;
    }
}

/// <summary>长度推导结果。</summary>
/// <param name="Length">推导出的字节长度；0 表示无法确定。</param>
/// <param name="Confidence">置信度。</param>
/// <param name="Note">推导依据说明。</param>
/// <param name="Structure">顺带解析出的结构树（可为空）。</param>
public sealed record MeasureResult(
    int Length,
    Confidence Confidence,
    string Note,
    IReadOnlyList<StructureNode>? Structure = null)
{
    /// <summary>未知长度的占位结果。</summary>
    public static MeasureResult Unknown(string note) => new(0, Confidence.Low, note);
}
