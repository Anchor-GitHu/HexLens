namespace HexLens.Core.Stego;

/// <summary>
/// 通道枚举（与 RGBA 的字节顺序一致）。
/// </summary>
[Flags]
public enum ChannelMask
{
    None = 0,
    R = 1,
    G = 2,
    B = 4,
    A = 8,
    Rgb = R | G | B,
    Rgba = R | G | B | A,
}

/// <summary>
/// 样本网格：LSB 提取的通用输入。图像是"每像素 4 通道"，音频是"每采样点 N 声道字节"，
/// 抽象成同一个接口后，图像与音频共用同一套位平面提取代码。
/// </summary>
public interface ISampleGrid
{
    /// <summary>样本点数量（图像 = 宽 × 高，音频 = 帧数）。</summary>
    int Count { get; }

    /// <summary>每个样本点的通道数。</summary>
    int ChannelCount { get; }

    /// <summary>行优先排布时每行的样本数（图像 = 宽，音频 = 帧数）。</summary>
    int LayoutWidth { get; }

    /// <summary>行数（图像 = 高，音频 = 1）。</summary>
    int LayoutHeight { get; }

    /// <summary>取某个通道值（0..255）。</summary>
    int GetSample(int index, int channel);

    /// <summary>载体描述（界面展示与报告用）。</summary>
    string Describe { get; }
}

/// <summary>解码后的位图：RGBA8 紧密排列。</summary>
public sealed class RasterImage(int width, int height, byte[] rgba, string describe) : ISampleGrid
{
    /// <summary>宽。</summary>
    public int Width { get; } = width;

    /// <summary>高。</summary>
    public int Height { get; } = height;

    /// <summary>RGBA 字节（长度 = 宽 × 高 × 4）。</summary>
    public byte[] Rgba { get; } = rgba;

    /// <inheritdoc />
    public int Count => Width * Height;

    /// <inheritdoc />
    public int ChannelCount => 4;

    /// <inheritdoc />
    public int LayoutWidth => Width;

    /// <inheritdoc />
    public int LayoutHeight => Height;

    /// <inheritdoc />
    public string Describe { get; } = describe;

    /// <inheritdoc />
    public int GetSample(int index, int channel) => Rgba[index * 4 + channel];
}

/// <summary>音频样本网格（PCM 采样点，每样本字节摊成独立通道）。</summary>
public sealed class AudioSamples(int frameCount, int channels, byte[][] channelData, string describe) : ISampleGrid
{
    /// <summary>帧数。</summary>
    public int Frames { get; } = frameCount;

    /// <summary>每通道的字节序列。</summary>
    public byte[][] ChannelData { get; } = channelData;

    /// <summary>采样率（若可解析）。</summary>
    public int SampleRate { get; init; }

    /// <summary>位深。</summary>
    public int BitsPerSample { get; init; }

    /// <inheritdoc />
    public int Count => Frames;

    /// <inheritdoc />
    public int ChannelCount => channels;

    /// <inheritdoc />
    public int LayoutWidth => Frames;

    /// <inheritdoc />
    public int LayoutHeight => 1;

    /// <inheritdoc />
    public string Describe { get; } = describe;

    /// <inheritdoc />
    public int GetSample(int index, int channel) => ChannelData[channel][index];
}
