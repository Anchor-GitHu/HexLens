namespace HexLens.Core.Util;

/// <summary>
/// 位流写入器：隐写分析里"每个像素/样本取低位拼字节"是核心动作，
/// 单独抽出来可同时服务图像 LSB、音频 LSB、以及任意自定义位序。
/// </summary>
public sealed class BitWriter
{
    private byte[] _buffer;
    private long _bitCount;

    /// <summary>创建写入器。</summary>
    /// <param name="capacityBytes">初始容量（估算值，可自动增长）。</param>
    public BitWriter(int capacityBytes = 256)
    {
        _buffer = new byte[Math.Max(16, capacityBytes)];
    }

    /// <summary>已写入的位数。</summary>
    public long BitCount => _bitCount;

    /// <summary>已写满的完整字节数。</summary>
    public int ByteCount => (int)(_bitCount / 8);

    /// <summary>写入一个位（0 或 1）。</summary>
    public void WriteBit(int bit)
    {
        int byteIndex = (int)(_bitCount >> 3);
        int bitIndex = (int)(_bitCount & 7);

        if (byteIndex >= _buffer.Length) Array.Resize(ref _buffer, Math.Max(_buffer.Length * 2, byteIndex + 64));
        else if (bitIndex == 0) _buffer[byteIndex] = 0;

        // 低位优先：第一个写入的位落在字节的最低位
        if ((bit & 1) != 0) _buffer[byteIndex] |= (byte)(1 << bitIndex);
        _bitCount++;
    }

    /// <summary>按低位优先写入一个整数的低 count 位。</summary>
    public void WriteBitsLowFirst(int value, int count)
    {
        for (int i = 0; i < count; i++) WriteBit((value >> i) & 1);
    }

    /// <summary>按高位优先写入一个整数的低 count 位。</summary>
    public void WriteBitsHighFirst(int value, int count)
    {
        for (int i = count - 1; i >= 0; i--) WriteBit((value >> i) & 1);
    }

    /// <summary>取出已写好的字节（未满一字节的尾部按 0 补齐）。</summary>
    public byte[] ToArray()
    {
        int n = (int)((_bitCount + 7) / 8);
        return _buffer.AsSpan(0, (int)n).ToArray();
    }

    /// <summary>已写好的字节视图。</summary>
    public ReadOnlySpan<byte> Span => _buffer.AsSpan(0, (int)((_bitCount + 7) / 8));

    /// <summary>丢弃全部内容以便复用。</summary>
    public void Reset() => _bitCount = 0;
}

/// <summary>位流读取器（低位优先或高位优先）。</summary>
public sealed class BitReader(ReadOnlySpan<byte> data, bool lsbFirst = true)
{
    private readonly byte[] _data = data.ToArray();

    /// <summary>总位数。</summary>
    public long BitCount => (long)_data.Length * 8;

    /// <summary>当前读取位置（位）。</summary>
    public long Position { get; private set; }

    /// <summary>剩余位数。</summary>
    public long Remaining => BitCount - Position;

    /// <summary>读一个位。</summary>
    public int ReadBit()
    {
        if (Position >= BitCount) throw new EndOfStreamException("位流已耗尽");
        int byteIndex = (int)(Position >> 3);
        int bitIndex = (int)(Position & 7);
        Position++;
        int shift = lsbFirst ? bitIndex : 7 - bitIndex;
        return (_data[byteIndex] >> shift) & 1;
    }

    /// <summary>读一个位，越界返回 false。</summary>
    public bool TryReadBit(out int bit)
    {
        if (Position >= BitCount) { bit = 0; return false; }
        bit = ReadBit();
        return true;
    }

    /// <summary>读 count 位组成整数（低位优先时第一个位是结果的最低位）。</summary>
    public int ReadBits(int count)
    {
        if (count is < 0 or > 32) throw new ArgumentOutOfRangeException(nameof(count));
        int value = 0;
        if (lsbFirst)
        {
            for (int i = 0; i < count; i++) value |= ReadBit() << i;
        }
        else
        {
            for (int i = 0; i < count; i++) value = (value << 1) | ReadBit();
        }
        return value;
    }

    /// <summary>跳过若干位。</summary>
    public void Skip(long bits)
    {
        if (bits < 0) throw new ArgumentOutOfRangeException(nameof(bits));
        Position = Math.Min(BitCount, Position + bits);
    }
}
