using System.IO.Compression;
using System.Text;
using HexLens.Core.Util;

namespace HexLens.Core.Stego;

/// <summary>
/// PNG 解码器（自实现，零外部依赖）。
/// 隐写分析必须拿到真实像素，而 LSB 提取又要求逐字节可控，
/// 所以这里把 PNG 的 zlib/滤波/位深解包全部自己走一遍。
/// </summary>
public static class PngDecoder
{
    private static readonly byte[] Signature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    /// <summary>解压输出上限：防止 PNG 解压炸弹。</summary>
    private const long MaxInflateBytes = 512L * 1024 * 1024;

    /// <summary>
    /// 解码 PNG 为 RGBA8。
    /// </summary>
    /// <param name="data">缓冲区。</param>
    /// <param name="start">PNG 起点。</param>
    /// <param name="error">失败原因。</param>
    public static RasterImage? Decode(ReadOnlySpan<byte> data, int start, out string error)
    {
        error = string.Empty;
        if (start < 0 || start + 8 > data.Length || !data.Slice(start, 8).SequenceEqual(Signature))
        {
            error = "起点不是 PNG 签名";
            return null;
        }

        int width = 0, height = 0, bitDepth = 0, colorType = 0, interlace = 0;
        byte[]? palette = null;
        byte[]? transparency = null;
        using var idat = new MemoryStream();
        bool sawIhdr = false;
        bool sawIend = false;

        int pos = start + 8;
        while (pos + 12 <= data.Length)
        {
            uint len = ByteOrder.U32BE(data, pos);
            if (len > int.MaxValue - 12) break;
            int dataLen = (int)len;
            if (pos + 12 + dataLen > data.Length) break;

            string type = Encoding.ASCII.GetString(data.Slice(pos + 4, 4));
            ReadOnlySpan<byte> chunk = data.Slice(pos + 8, dataLen);

            switch (type)
            {
                case "IHDR":
                    if (dataLen < 13) { error = "IHDR 长度不足"; return null; }
                    width = (int)ByteOrder.U32BE(chunk, 0);
                    height = (int)ByteOrder.U32BE(chunk, 4);
                    bitDepth = chunk[8];
                    colorType = chunk[9];
                    interlace = chunk[12];
                    sawIhdr = true;
                    break;

                case "PLTE":
                    palette = chunk.ToArray();
                    break;

                case "tRNS":
                    transparency = chunk.ToArray();
                    break;

                case "IDAT":
                    idat.Write(chunk);
                    break;

                case "IEND":
                    sawIend = true;
                    break;
            }

            pos += 12 + dataLen;
            if (sawIend) break;
        }

        if (!sawIhdr) { error = "未找到 IHDR"; return null; }
        if (width <= 0 || height <= 0) { error = $"图像尺寸非法（{width}×{height}）"; return null; }
        if (interlace != 0) { error = "Adam7 隔行 PNG 暂不支持像素级分析"; return null; }
        if (bitDepth is not (1 or 2 or 4 or 8 or 16)) { error = $"不支持的位深 {bitDepth}"; return null; }

        int channels = colorType switch
        {
            0 => 1,
            2 => 3,
            3 => 1,
            4 => 2,
            6 => 4,
            _ => -1,
        };
        if (channels < 0) { error = $"不支持的颜色类型 {colorType}"; return null; }
        if (colorType == 3 && palette is null) { error = "索引色 PNG 缺少 PLTE"; return null; }

        long rawLength = (long)((width * channels * bitDepth + 7) / 8 + 1) * height;
        if (rawLength > MaxInflateBytes)
        {
            error = $"解码后数据 {rawLength / 1048576} MiB 超过上限";
            return null;
        }

        byte[] raw;
        try
        {
            raw = Inflate(idat.ToArray(), (int)rawLength, out string inflateError);
            if (inflateError.Length > 0) { error = inflateError; return null; }
        }
        catch (Exception ex)
        {
            error = $"IDAT 解压失败：{ex.Message}";
            return null;
        }

        int bitsPerPixel = channels * bitDepth;
        int stride = (width * bitsPerPixel + 7) / 8;
        int filterUnit = Math.Max(1, bitsPerPixel / 8);
        byte[] pixels = new byte[(int)((long)stride * height)];

        int cursor = 0;
        for (int y = 0; y < height; y++)
        {
            if (cursor + 1 + stride > raw.Length)
            {
                error = $"解压数据不足（第 {y} 行）";
                return null;
            }
            byte filter = raw[cursor++];
            UnfilterRow(pixels, stride, filterUnit, y, filter, raw.AsSpan(cursor, stride));
            cursor += stride;
        }

        byte[] rgba = ToRgba(pixels, width, height, bitDepth, colorType, channels, palette, transparency);
        string describe = $"PNG {width}×{height}，{bitDepth} 位，颜色类型 {colorType}"
                          + (sawIend ? string.Empty : "（块链未正常结束）");
        return new RasterImage(width, height, rgba, describe);
    }

    private static byte[] Inflate(byte[] compressed, int expectedLength, out string error)
    {
        error = string.Empty;
        using var input = new MemoryStream(compressed);
        using var z = new ZLibStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream(Math.Min(expectedLength, 1 << 24));

        byte[] buffer = new byte[65536];
        long total = 0;
        int read;
        while ((read = z.Read(buffer, 0, buffer.Length)) > 0)
        {
            total += read;
            if (total > MaxInflateBytes)
            {
                error = "解压输出超过上限（疑似解压炸弹）";
                return [];
            }
            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }

    /// <summary>PNG 行滤波反演（就地操作，需要上一行已还原）。</summary>
    private static void UnfilterRow(byte[] pixels, int stride, int filterUnit, int y, byte filter, ReadOnlySpan<byte> source)
    {
        int rowStart = y * stride;
        source.CopyTo(pixels.AsSpan(rowStart, stride));
        if (filter == 0) return;

        for (int i = 0; i < stride; i++)
        {
            int left = i >= filterUnit ? pixels[rowStart + i - filterUnit] : 0;
            int up = y > 0 ? pixels[rowStart - stride + i] : 0;
            int upLeft = y > 0 && i >= filterUnit ? pixels[rowStart - stride + i - filterUnit] : 0;
            int x = pixels[rowStart + i];

            int value = filter switch
            {
                1 => x + left,
                2 => x + up,
                3 => x + ((left + up) >> 1),
                4 => x + Paeth(left, up, upLeft),
                _ => x,
            };
            pixels[rowStart + i] = (byte)value;
        }
    }

    private static int Paeth(int a, int b, int c)
    {
        int p = a + b - c;
        int pa = Math.Abs(p - a);
        int pb = Math.Abs(p - b);
        int pc = Math.Abs(p - c);
        if (pa <= pb && pa <= pc) return a;
        return pb <= pc ? b : c;
    }

    private static byte[] ToRgba(
        byte[] pixels, int width, int height, int bitDepth, int colorType, int channels,
        byte[]? palette, byte[]? transparency)
    {
        var rgba = new byte[width * height * 4];
        int stride = (width * channels * bitDepth + 7) / 8;
        int maxValue = (1 << bitDepth) - 1;

        for (int y = 0; y < height; y++)
        {
            ReadOnlySpan<byte> row = pixels.AsSpan(y * stride, stride);
            for (int x = 0; x < width; x++)
            {
                int outIndex = (y * width + x) * 4;
                switch (colorType)
                {
                    case 0:   // 灰度
                    {
                        int g = ScaleGray(GetSample(row, x, bitDepth), bitDepth, maxValue);
                        byte alpha = 255;
                        if (transparency is { Length: >= 2 })
                        {
                            int transparentGray = (transparency[0] << 8) | transparency[1];
                            if (GetSample(row, x, bitDepth) == transparentGray) alpha = 0;
                        }
                        rgba[outIndex] = rgba[outIndex + 1] = rgba[outIndex + 2] = (byte)g;
                        rgba[outIndex + 3] = alpha;
                        break;
                    }

                    case 2:   // 真彩
                    {
                        rgba[outIndex] = (byte)ScaleSample(GetSample(row, x * 3, bitDepth), bitDepth, maxValue);
                        rgba[outIndex + 1] = (byte)ScaleSample(GetSample(row, x * 3 + 1, bitDepth), bitDepth, maxValue);
                        rgba[outIndex + 2] = (byte)ScaleSample(GetSample(row, x * 3 + 2, bitDepth), bitDepth, maxValue);
                        rgba[outIndex + 3] = 255;
                        break;
                    }

                    case 3:   // 索引色
                    {
                        int index = GetSample(row, x, bitDepth);
                        int p = index * 3;
                        if (palette is not null && p + 2 < palette.Length)
                        {
                            rgba[outIndex] = palette[p];
                            rgba[outIndex + 1] = palette[p + 1];
                            rgba[outIndex + 2] = palette[p + 2];
                        }
                        rgba[outIndex + 3] = transparency is not null && index < transparency.Length
                            ? transparency[index]
                            : (byte)255;
                        break;
                    }

                    case 4:   // 灰度 + Alpha
                    {
                        int g = ScaleGray(GetSample(row, x * 2, bitDepth), bitDepth, maxValue);
                        rgba[outIndex] = rgba[outIndex + 1] = rgba[outIndex + 2] = (byte)g;
                        rgba[outIndex + 3] = (byte)ScaleSample(GetSample(row, x * 2 + 1, bitDepth), bitDepth, maxValue);
                        break;
                    }

                    case 6:   // 真彩 + Alpha
                    {
                        rgba[outIndex] = (byte)ScaleSample(GetSample(row, x * 4, bitDepth), bitDepth, maxValue);
                        rgba[outIndex + 1] = (byte)ScaleSample(GetSample(row, x * 4 + 1, bitDepth), bitDepth, maxValue);
                        rgba[outIndex + 2] = (byte)ScaleSample(GetSample(row, x * 4 + 2, bitDepth), bitDepth, maxValue);
                        rgba[outIndex + 3] = (byte)ScaleSample(GetSample(row, x * 4 + 3, bitDepth), bitDepth, maxValue);
                        break;
                    }
                }
            }
        }
        return rgba;
    }

    private static int ScaleGray(int value, int bitDepth, int maxValue) => bitDepth switch
    {
        1 => value * 255,
        2 => value * 85,
        4 => value * 17,
        _ => ScaleSample(value, bitDepth, maxValue),
    };

    private static int ScaleSample(int value, int bitDepth, int maxValue)
    {
        if (bitDepth == 16) return value;                       // 已取高字节
        if (bitDepth == 8) return value;
        return maxValue == 0 ? value : value * 255 / maxValue;
    }

    /// <summary>按位深从行中取第 index 个样本（16 位取高字节，保持 0..255 语义）。</summary>
    private static int GetSample(ReadOnlySpan<byte> row, int index, int bitDepth) => bitDepth switch
    {
        8 => index < row.Length ? row[index] : 0,
        16 => index * 2 < row.Length ? row[index * 2] : 0,
        1 => (row[index >> 3] >> (7 - (index & 7))) & 1,
        2 => (row[index >> 2] >> (6 - 2 * (index & 3))) & 3,
        4 => (row[index >> 1] >> (4 - 4 * (index & 1))) & 0xF,
        _ => 0,
    };
}
