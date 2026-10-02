namespace HexLens.Core.Stego;

/// <summary>GIF 帧信息（不做合成，逐帧独立解码，便于"每帧藏一段"的分析）。</summary>
public sealed record GifFrameInfo(
    int Offset,
    int Length,
    int Left,
    int Top,
    int Width,
    int Height,
    int DelayCentiseconds,
    bool Interlaced,
    int TransparentIndex,
    int LocalPaletteEntries);

/// <summary>
/// GIF 解码器：自带 LZW 解码，用于多帧 GIF 的逐帧像素分析。
/// CTF 里 GIF 的价值主要在"帧数"和"逐帧像素 LSB"，所以这里逐帧给数据，不做叠加合成。
/// </summary>
public static class GifDecoder
{
    /// <summary>列出全部帧及其布局信息。</summary>
    public static List<GifFrameInfo> ListFrames(ReadOnlySpan<byte> data, int start, out string error)
    {
        var frames = new List<GifFrameInfo>();
        error = string.Empty;

        if (!TryReadHeader(data, start, out int width, out int height, out byte packed, out error))
            return frames;

        bool hasGct = (packed & 0x80) != 0;
        int gctSize = hasGct ? 3 * (1 << ((packed & 0x07) + 1)) : 0;
        int pos = start + 13 + gctSize;

        int pendingDelay = 0;
        int pendingTransparent = -1;

        while (pos < data.Length)
        {
            byte block = data[pos];

            if (block == 0x3B) break;

            if (block == 0x21)
            {
                if (pos + 2 > data.Length) break;
                byte label = data[pos + 1];
                int bodyStart = pos + 2;
                if (label == 0xF9 && bodyStart + 6 <= data.Length && data[bodyStart] >= 4)
                {
                    byte gcePacked = data[bodyStart + 1];
                    pendingDelay = data[bodyStart + 2] | (data[bodyStart + 3] << 8);
                    pendingTransparent = (gcePacked & 0x01) != 0 ? data[bodyStart + 4] : -1;
                }
                pos = SkipSubBlocks(data, bodyStart);
                continue;
            }

            if (block == 0x2C)
            {
                if (pos + 10 > data.Length) break;
                int left = data[pos + 1] | (data[pos + 2] << 8);
                int top = data[pos + 3] | (data[pos + 4] << 8);
                int fw = data[pos + 5] | (data[pos + 6] << 8);
                int fh = data[pos + 7] | (data[pos + 8] << 8);
                byte lp = data[pos + 9];
                bool hasLct = (lp & 0x80) != 0;
                int lctEntries = hasLct ? 1 << ((lp & 0x07) + 1) : 0;
                int lctSize = lctEntries * 3;
                bool interlaced = (lp & 0x40) != 0;

                int dataPos = pos + 10 + lctSize;
                int subBlocksStart = dataPos;
                int end = SkipSubBlocks(data, dataPos + 1);

                frames.Add(new GifFrameInfo(pos, end - pos, left, top, fw, fh,
                    pendingDelay, interlaced, pendingTransparent, lctEntries));

                pendingDelay = 0;
                pendingTransparent = -1;
                _ = subBlocksStart;
                pos = end;
                continue;
            }

            break;
        }

        _ = width;
        _ = height;
        return frames;
    }

    /// <summary>解码前若干帧为 RGBA8。</summary>
    public static List<RasterImage> DecodeFrames(ReadOnlySpan<byte> data, int start, int maxFrames, out string error)
    {
        var result = new List<RasterImage>();
        error = string.Empty;

        if (!TryReadHeader(data, start, out int _, out int _, out byte packed, out error))
            return result;

        byte[]? globalPalette = null;
        bool hasGct = (packed & 0x80) != 0;
        if (hasGct)
        {
            int gctEntries = 1 << ((packed & 0x07) + 1);
            globalPalette = ReadPalette(data, start + 13, gctEntries);
        }
        int gctSize = hasGct ? 3 * (1 << ((packed & 0x07) + 1)) : 0;

        int pos = start + 13 + gctSize;
        int transparentIndex = -1;

        while (pos < data.Length && result.Count < maxFrames)
        {
            byte block = data[pos];
            if (block == 0x3B) break;

            if (block == 0x21)
            {
                if (pos + 2 > data.Length) break;
                byte label = data[pos + 1];
                int bodyStart = pos + 2;
                if (label == 0xF9 && bodyStart + 6 <= data.Length)
                {
                    byte gcePacked = data[bodyStart + 1];
                    transparentIndex = (gcePacked & 0x01) != 0 ? data[bodyStart + 4] : -1;
                }
                pos = SkipSubBlocks(data, bodyStart);
                continue;
            }

            if (block != 0x2C) break;
            if (pos + 10 > data.Length) break;

            int left = data[pos + 1] | (data[pos + 2] << 8);
            int top = data[pos + 3] | (data[pos + 4] << 8);
            int fw = data[pos + 5] | (data[pos + 6] << 8);
            int fh = data[pos + 7] | (data[pos + 8] << 8);
            byte lp = data[pos + 9];
            bool hasLct = (lp & 0x80) != 0;
            int lctEntries = hasLct ? 1 << ((lp & 0x07) + 1) : 0;
            bool interlaced = (lp & 0x40) != 0;

            byte[]? palette = globalPalette;
            int colorCount = globalPalette is null ? 0 : globalPalette.Length / 3;
            if (hasLct)
            {
                palette = ReadPalette(data, pos + 10, lctEntries);
                colorCount = lctEntries;
            }

            int lzwPos = pos + 10 + (hasLct ? lctEntries * 3 : 0);
            if (lzwPos >= data.Length) break;

            int minCodeSize = data[lzwPos];
            int dataEnd = SkipSubBlocks(data, lzwPos + 1);
            byte[] compressed = ConcatSubBlocks(data, lzwPos + 1, dataEnd);

            int expected = fw * fh;
            byte[] indices = DecodeLzw(compressed, minCodeSize, expected);
            if (indices.Length < expected)
            {
                // 数据不足时按已有内容解码，不中断整体分析
                expected = indices.Length;
            }

            if (palette is null || fw <= 0 || fh <= 0)
            {
                pos = dataEnd;
                continue;
            }

            var rgba = new byte[fw * fh * 4];
            int target = 0;
            for (int y = 0; y < fh; y++)
            {
                int sourceRow = interlaced ? InterlacedRow(y, fh) : y;
                for (int x = 0; x < fw; x++)
                {
                    int srcIndex = sourceRow * fw + x;
                    int paletteIndex = srcIndex < indices.Length ? indices[srcIndex] : 0;
                    int p = paletteIndex * 3;
                    int outIndex = target * 4;
                    if (p + 2 < palette.Length)
                    {
                        rgba[outIndex] = palette[p];
                        rgba[outIndex + 1] = palette[p + 1];
                        rgba[outIndex + 2] = palette[p + 2];
                    }
                    rgba[outIndex + 3] = paletteIndex == transparentIndex ? (byte)0 : (byte)255;
                    target++;
                }
            }

            result.Add(new RasterImage(fw, fh, rgba,
                $"GIF 第 {result.Count + 1} 帧 {fw}×{fh} @ ({left},{top})，{colorCount} 色"
                + (interlaced ? "，隔行" : string.Empty)));

            pos = dataEnd;
        }

        if (result.Count == 0) error = "未解出任何 GIF 帧";
        return result;
    }

    private static bool TryReadHeader(ReadOnlySpan<byte> data, int start, out int width, out int height, out byte packed, out string error)
    {
        width = height = 0;
        packed = 0;
        error = string.Empty;

        if (start + 13 > data.Length) { error = "GIF 头不完整"; return false; }
        if (data[start] != 'G' || data[start + 1] != 'I' || data[start + 2] != 'F') { error = "起点不是 GIF"; return false; }

        width = data[start + 6] | (data[start + 7] << 8);
        height = data[start + 8] | (data[start + 9] << 8);
        packed = data[start + 10];
        if (width <= 0 || height <= 0) { error = "GIF 逻辑屏幕尺寸非法"; return false; }
        return true;
    }

    private static byte[] ReadPalette(ReadOnlySpan<byte> data, int offset, int entries)
    {
        var palette = new byte[entries * 3];
        for (int i = 0; i < entries; i++)
        {
            int p = offset + i * 3;
            if (p + 2 >= data.Length) break;
            palette[i * 3] = data[p];
            palette[i * 3 + 1] = data[p + 1];
            palette[i * 3 + 2] = data[p + 2];
        }
        return palette;
    }

    private static int SkipSubBlocks(ReadOnlySpan<byte> data, int pos)
    {
        while (pos < data.Length)
        {
            int size = data[pos];
            pos++;
            if (size == 0) break;
            pos += size;
        }
        return Math.Min(pos, data.Length);
    }

    private static byte[] ConcatSubBlocks(ReadOnlySpan<byte> data, int pos, int end)
    {
        using var ms = new MemoryStream();
        while (pos < data.Length && pos < end)
        {
            int size = data[pos];
            pos++;
            if (size == 0) break;
            int take = Math.Min(size, Math.Min(data.Length, end) - pos);
            if (take <= 0) break;
            ms.Write(data.Slice(pos, take));
            pos += size;
        }
        return ms.ToArray();
    }

    /// <summary>GIF 帧内隔行的 4 遍扫描行序映射。</summary>
    private static int InterlacedRow(int y, int height)
    {
        int[] starts = [0, 4, 2, 1];
        int[] steps = [8, 8, 4, 2];
        for (int pass = 0; pass < 4; pass++)
        {
            int rows = (height - starts[pass] + steps[pass] - 1) / steps[pass];
            if (rows < 0) rows = 0;
            if (y < rows) return starts[pass] + y * steps[pass];
            y -= rows;
        }
        return height - 1;
    }

    /// <summary>GIF 变长 LZW 解码。</summary>
    private static byte[] DecodeLzw(byte[] data, int minCodeSize, int expected)
    {
        var output = new List<byte>(Math.Max(expected, 256));
        if (minCodeSize is < 2 or > 11) return [];

        int clearCode = 1 << minCodeSize;
        int endCode = clearCode + 1;
        int codeSize = minCodeSize + 1;
        int nextCode = endCode + 1;

        int[] prefix = new int[4096];
        byte[] suffix = new byte[4096];
        byte[] first = new byte[4096];
        byte[] stack = new byte[4096];

        for (int i = 0; i < clearCode; i++)
        {
            prefix[i] = -1;
            suffix[i] = (byte)i;
            first[i] = (byte)i;
        }

        int bitBuffer = 0, bitCount = 0, dataPos = 0;
        int previous = -1;

        while (true)
        {
            while (bitCount < codeSize)
            {
                if (dataPos >= data.Length) break;
                bitBuffer |= data[dataPos++] << bitCount;
                bitCount += 8;
            }
            if (bitCount < codeSize) break;

            int code = bitBuffer & ((1 << codeSize) - 1);
            bitBuffer >>= codeSize;
            bitCount -= codeSize;

            if (code == clearCode)
            {
                codeSize = minCodeSize + 1;
                nextCode = endCode + 1;
                previous = -1;
                continue;
            }
            if (code == endCode) break;

            int stackTop = 0;
            int current = code;

            if (code >= nextCode)
            {
                if (previous < 0) break;
                stack[stackTop++] = first[previous];
                current = previous;
            }

            bool broken = false;
            while (current >= clearCode)
            {
                if (current >= nextCode || stackTop >= 4095) { broken = true; break; }
                stack[stackTop++] = suffix[current];
                current = prefix[current];
            }
            if (broken) break;

            stack[stackTop++] = (byte)current;

            byte firstByte = stack[stackTop - 1];
            for (int i = stackTop - 1; i >= 0; i--) output.Add(stack[i]);

            if (previous >= 0 && nextCode < 4096)
            {
                prefix[nextCode] = previous;
                suffix[nextCode] = firstByte;
                first[nextCode] = first[previous];
                nextCode++;
                if (nextCode >= (1 << codeSize) && codeSize < 12) codeSize++;
            }
            previous = code;
        }

        return output.ToArray();
    }
}
