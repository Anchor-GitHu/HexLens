using System.Text;

namespace HexLens.Core.Analysis;

/// <summary>
/// 把一段字节按各种数值 / 文本类型解释出来 —— 对标 010 Editor 右侧的 Data Inspector。
///
/// 放在 Core 而不是界面里：这是纯计算，可以单测；界面只负责显示。
/// </summary>
public static class DataInspector
{
    /// <summary>一条解释结果。</summary>
    /// <param name="Name">类型名（binary / uint8 / float32 / ASCII…）。</param>
    /// <param name="Value">解释出的值。</param>
    public sealed record Entry(string Name, string Value);

    /// <summary>文本类解释最多取多少字节（太长没意义）。</summary>
    private const int TextProbe = 24;

    static DataInspector()
    {
        // GB18030 / BIG5 / SHIFT-JIS 属于代码页编码，.NET Core 起需要显式注册提供程序。
        // 注册失败就退化为"只支持内置编码"，不会抛异常。
        try
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        }
        catch
        {
            // 忽略：拿不到的编码在下面会被跳过
        }
    }

    /// <summary>按给定字节序解释这段字节。</summary>
    public static List<Entry> Inspect(ReadOnlySpan<byte> data, bool littleEndian)
    {
        var list = new List<Entry>();
        if (data.Length == 0) return list;

        byte first = data[0];
        list.Add(new Entry("binary", Convert.ToString(first, 2).PadLeft(8, '0')));
        list.Add(new Entry("octal", Convert.ToString(first, 8).PadLeft(3, '0')));

        AddInteger(list, "uint8", data, 1, false, littleEndian, unsigned: true);
        AddInteger(list, "int8", data, 1, false, littleEndian, unsigned: false);
        AddInteger(list, "uint16", data, 2, false, littleEndian, unsigned: true);
        AddInteger(list, "int16", data, 2, false, littleEndian, unsigned: false);
        AddInteger(list, "uint24", data, 3, false, littleEndian, unsigned: true);
        AddInteger(list, "int24", data, 3, false, littleEndian, unsigned: false);
        AddInteger(list, "uint32", data, 4, false, littleEndian, unsigned: true);
        AddInteger(list, "int32", data, 4, false, littleEndian, unsigned: false);
        AddInteger(list, "uint64", data, 8, false, littleEndian, unsigned: true);
        AddInteger(list, "int64", data, 8, false, littleEndian, unsigned: false);

        AddLeb128(list, data, signed: false);
        AddLeb128(list, data, signed: true);

        AddFloat(list, "float16", data, 2, littleEndian);
        AddFloat(list, "bfloat16", data, 2, littleEndian);
        AddFloat(list, "float32", data, 4, littleEndian);
        AddFloat(list, "float64", data, 8, littleEndian);

        // GUID：需要 16 字节。前 4/2/2 字节按小端、后 8 字节顺序固定，这是 Windows 的写法。
        list.Add(new Entry("GUID", data.Length >= 16 ? FormatGuid(data) : "(需要 16 字节)"));

        AddText(list, "ASCII", data, Encoding.ASCII);
        AddText(list, "UTF-8", data, Encoding.UTF8);
        AddText(list, "UTF-16LE", data, Encoding.Unicode);
        AddText(list, "UTF-16BE", data, Encoding.BigEndianUnicode);
        AddText(list, "Latin-1", data, Encoding.Latin1);
        AddText(list, "GB18030", data, TryGetEncoding("GB18030"));
        AddText(list, "BIG5", data, TryGetEncoding("big5"));
        AddText(list, "SHIFT-JIS", data, TryGetEncoding("shift_jis"));

        return list;
    }

    // ── 整数 ──────────────────────────────────────────────────────────────

    private static void AddInteger(List<Entry> list, string name, ReadOnlySpan<byte> data,
        int size, bool _, bool littleEndian, bool unsigned)
    {
        if (data.Length < size)
        {
            list.Add(new Entry(name, $"(需要 {size} 字节)"));
            return;
        }

        ReadOnlySpan<byte> slice = data[..size];
        Span<byte> buffer = stackalloc byte[8];
        slice.CopyTo(buffer);

        long value = littleEndian
            ? ReadLittleEndian(buffer, size)
            : ReadBigEndian(buffer, size);

        if (size == 8)
        {
            // 64 位：无符号直接用 ulong 显示，避免负数看着别扭
            ulong raw = littleEndian ? ReadLittleEndian64(buffer) : ReadBigEndian64(buffer);
            list.Add(new Entry(name, unsigned ? raw.ToString() : unchecked((long)raw).ToString()));
            return;
        }

        if (unsigned && value < 0) value += 1L << (size * 8);
        list.Add(new Entry(name, value.ToString()));
    }

    private static long ReadLittleEndian(ReadOnlySpan<byte> buffer, int size)
    {
        long value = 0;
        for (int i = size - 1; i >= 0; i--) value = (value << 8) | buffer[i];

        // 有符号扩展
        int bits = size * 8;
        long signBit = 1L << (bits - 1);
        if (bits < 64 && (value & signBit) != 0) value -= 1L << bits;
        return value;
    }

    private static long ReadBigEndian(ReadOnlySpan<byte> buffer, int size)
    {
        long value = 0;
        for (int i = 0; i < size; i++) value = (value << 8) | buffer[i];

        int bits = size * 8;
        long signBit = 1L << (bits - 1);
        if (bits < 64 && (value & signBit) != 0) value -= 1L << bits;
        return value;
    }

    private static ulong ReadLittleEndian64(ReadOnlySpan<byte> buffer)
    {
        ulong value = 0;
        for (int i = 7; i >= 0; i--) value = (value << 8) | buffer[i];
        return value;
    }

    private static ulong ReadBigEndian64(ReadOnlySpan<byte> buffer)
    {
        ulong value = 0;
        for (int i = 0; i < 8; i++) value = (value << 8) | buffer[i];
        return value;
    }

    // ── LEB128 ────────────────────────────────────────────────────────────

    private static void AddLeb128(List<Entry> list, ReadOnlySpan<byte> data, bool signed)
    {
        string name = signed ? "SLEB128" : "ULEB128";
        long value = 0;
        int shift = 0;
        int used = 0;

        foreach (byte b in data)
        {
            if (used >= 10) break;                       // 最多 10 字节，防跑飞
            if (signed)
            {
                value |= (long)(b & 0x7F) << shift;
                shift += 7;
                if ((b & 0x80) == 0)
                {
                    if (shift < 64 && (b & 0x40) != 0) value |= -(1L << shift);
                    used++;
                    break;
                }
            }
            else
            {
                value |= (long)(b & 0x7F) << shift;
                shift += 7;
                if ((b & 0x80) == 0) { used++; break; }
            }
            used++;
        }

        list.Add(new Entry(name, used > 0 ? value.ToString() : "(无效)"));
    }

    // ── 浮点 ──────────────────────────────────────────────────────────────

    private static void AddFloat(List<Entry> list, string name, ReadOnlySpan<byte> data,
        int size, bool littleEndian)
    {
        if (data.Length < size)
        {
            list.Add(new Entry(name, $"(需要 {size} 字节)"));
            return;
        }

        ReadOnlySpan<byte> slice = data[..size];
        Span<byte> buffer = stackalloc byte[8];
        slice.CopyTo(buffer);

        if (!littleEndian) Array.Reverse(buffer.ToArray().AsSpan(0, size).ToArray());  // 占位，见下

        try
        {
            if (name == "bfloat16")
            {
                // bfloat16 = float32 的高 16 位
                ushort raw = littleEndian
                    ? (ushort)(buffer[0] | (buffer[1] << 8))
                    : (ushort)((buffer[0] << 8) | buffer[1]);
                uint bits = (uint)raw << 16;
                list.Add(new Entry(name, BitConverter.UInt32BitsToSingle(bits).ToString("G6")));
                return;
            }

            byte[] ordered = new byte[size];
            for (int i = 0; i < size; i++) ordered[i] = littleEndian ? buffer[i] : buffer[size - 1 - i];

            string text = name switch
            {
                "float16" => BitConverter.ToHalf(ordered, 0).ToString("G6"),
                "float32" => BitConverter.ToSingle(ordered, 0).ToString("G6"),
                "float64" => BitConverter.ToDouble(ordered, 0).ToString("G6"),
                _ => "?",
            };
            list.Add(new Entry(name, text));
        }
        catch (Exception ex)
        {
            list.Add(new Entry(name, $"(无法解释：{ex.GetType().Name})"));
        }
    }

    // ── 文本 ──────────────────────────────────────────────────────────────

    private static void AddText(List<Entry> list, string name, ReadOnlySpan<byte> data, Encoding? encoding)
    {
        if (encoding is null)
        {
            list.Add(new Entry(name, "(本机不支持该代码页)"));
            return;
        }

        int count = Math.Min(data.Length, TextProbe);
        try
        {
            string text = encoding.GetString(data[..count].ToArray());
            text = text.Replace("\r", " ").Replace("\n", " ").Replace("\0", string.Empty).Trim();
            list.Add(new Entry(name, text.Length == 0 ? "\"\"" : $"\"{text}\""));
        }
        catch
        {
            list.Add(new Entry(name, "(解码失败)"));
        }
    }

    private static Encoding? TryGetEncoding(string name)
    {
        try
        {
            return Encoding.GetEncoding(name);
        }
        catch
        {
            return null;
        }
    }

    private static string FormatGuid(ReadOnlySpan<byte> data)
    {
        // Windows GUID：前三个字段小端，其余按顺序
        uint a = (uint)(data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24));
        ushort b = (ushort)(data[4] | (data[5] << 8));
        ushort c = (ushort)(data[6] | (data[7] << 8));
        return $"{a:X8}-{b:X4}-{c:X4}-{data[8]:X2}{data[9]:X2}-"
             + $"{data[10]:X2}{data[11]:X2}{data[12]:X2}{data[13]:X2}{data[14]:X2}{data[15]:X2}";
    }
}
