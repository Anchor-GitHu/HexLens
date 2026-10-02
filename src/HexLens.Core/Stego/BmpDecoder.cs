using HexLens.Core.Util;

namespace HexLens.Core.Stego;

/// <summary>BMP 解码器（BI_RGB 与 32 位位域），面向 LSB 分析。</summary>
public static class BmpDecoder
{
    /// <summary>解码 BMP 为 RGBA8。</summary>
    public static RasterImage? Decode(ReadOnlySpan<byte> data, int start, out string error)
    {
        error = string.Empty;
        if (start + 26 > data.Length) { error = "BMP 头部不完整"; return null; }
        if (data[start] != 'B' || data[start + 1] != 'M') { error = "起点不是 BM"; return null; }

        uint dataOffset = ByteOrder.U32LE(data, start + 10);
        int dibSize = (int)ByteOrder.U32LE(data, start + 14);
        int width = (int)ByteOrder.U32LE(data, start + 18);
        int heightRaw = (int)ByteOrder.U32LE(data, start + 22);
        ushort bits = ByteOrder.U16LE(data, start + 28);
        uint compression = ByteOrder.U32LE(data, start + 30);
        uint colorsUsed = ByteOrder.U32LE(data, start + 46);

        if (dibSize < 40) { error = $"不支持的 DIB 头大小 {dibSize}（仅支持 BITMAPINFOHEADER 及以上）"; return null; }
        if (width <= 0) { error = $"宽度非法 {width}"; return null; }
        if (heightRaw == 0) { error = "高度为 0"; return null; }

        bool bottomUp = heightRaw > 0;
        int height = Math.Abs(heightRaw);

        if (compression is not (0 or 3))
        {
            error = $"不支持的压缩方式 {compression}（仅支持未压缩/位域）";
            return null;
        }
        if (bits is not (8 or 24 or 32))
        {
            error = $"不支持的位深 {bits}（仅支持 8/24/32）";
            return null;
        }

        // 调色板
        byte[]? palette = null;
        if (bits == 8)
        {
            int entries = colorsUsed != 0 ? (int)colorsUsed : 256;
            int paletteStart = start + 14 + dibSize;
            if (paletteStart + entries * 4 > data.Length) { error = "调色板越界"; return null; }
            palette = new byte[entries * 3];
            for (int i = 0; i < entries; i++)
            {
                palette[i * 3] = data[paletteStart + i * 4 + 2];      // R
                palette[i * 3 + 1] = data[paletteStart + i * 4 + 1];  // G
                palette[i * 3 + 2] = data[paletteStart + i * 4];      // B
            }
        }

        int stride = ((width * bits + 31) / 32) * 4;
        long needed = (long)dataOffset + (long)stride * height;
        if (needed > data.Length - start)
        {
            // 有些变体把像素数据长度算错，按剩余长度尽力解码
            int availableRows = (int)((data.Length - start - (int)dataOffset) / stride);
            if (availableRows <= 0) { error = "像素数据不足"; return null; }
            height = availableRows;
        }

        var rgba = new byte[width * height * 4];
        int pixelBase = start + (int)dataOffset;

        for (int row = 0; row < height; row++)
        {
            int srcRow = bottomUp ? height - 1 - row : row;
            int rowStart = pixelBase + srcRow * stride;
            if (rowStart + stride > data.Length) break;

            for (int x = 0; x < width; x++)
            {
                int outIndex = (row * width + x) * 4;
                switch (bits)
                {
                    case 8:
                    {
                        int index = data[rowStart + x];
                        int p = index * 3;
                        if (palette is not null && p + 2 < palette.Length)
                        {
                            rgba[outIndex] = palette[p];
                            rgba[outIndex + 1] = palette[p + 1];
                            rgba[outIndex + 2] = palette[p + 2];
                        }
                        rgba[outIndex + 3] = 255;
                        break;
                    }

                    case 24:
                    {
                        int p = rowStart + x * 3;
                        rgba[outIndex] = data[p + 2];
                        rgba[outIndex + 1] = data[p + 1];
                        rgba[outIndex + 2] = data[p];
                        rgba[outIndex + 3] = 255;
                        break;
                    }

                    case 32:
                    {
                        int p = rowStart + x * 4;
                        rgba[outIndex] = data[p + 2];
                        rgba[outIndex + 1] = data[p + 1];
                        rgba[outIndex + 2] = data[p];
                        rgba[outIndex + 3] = data[p + 3] == 0 ? (byte)255 : data[p + 3];
                        break;
                    }
                }
            }
        }

        return new RasterImage(width, height, rgba, $"BMP {width}×{height}，{bits} 位，{(bottomUp ? "自下而上" : "自上而下")}");
    }
}
