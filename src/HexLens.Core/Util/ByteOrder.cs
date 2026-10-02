namespace HexLens.Core.Util;

/// <summary>
/// 字节序读取工具。全部采用 Try 语义：解析来路不明的文件时越界不是异常，而是"结构到此为止"。
/// </summary>
public static class ByteOrder
{
    public static bool TryReadU16BE(ReadOnlySpan<byte> d, int offset, out ushort value)
    {
        if (offset < 0 || offset + 2 > d.Length) { value = 0; return false; }
        value = (ushort)((d[offset] << 8) | d[offset + 1]);
        return true;
    }

    public static bool TryReadU16LE(ReadOnlySpan<byte> d, int offset, out ushort value)
    {
        if (offset < 0 || offset + 2 > d.Length) { value = 0; return false; }
        value = (ushort)(d[offset] | (d[offset + 1] << 8));
        return true;
    }

    public static bool TryReadU32BE(ReadOnlySpan<byte> d, int offset, out uint value)
    {
        if (offset < 0 || offset + 4 > d.Length) { value = 0; return false; }
        value = ((uint)d[offset] << 24) | ((uint)d[offset + 1] << 16) | ((uint)d[offset + 2] << 8) | (uint)d[offset + 3];
        return true;
    }

    public static bool TryReadU32LE(ReadOnlySpan<byte> d, int offset, out uint value)
    {
        if (offset < 0 || offset + 4 > d.Length) { value = 0; return false; }
        value = (uint)d[offset] | ((uint)d[offset + 1] << 8) | ((uint)d[offset + 2] << 16) | ((uint)d[offset + 3] << 24);
        return true;
    }

    public static bool TryReadU64BE(ReadOnlySpan<byte> d, int offset, out ulong value)
    {
        if (offset < 0 || offset + 8 > d.Length) { value = 0; return false; }
        value = 0;
        for (int i = 0; i < 8; i++) value = (value << 8) | d[offset + i];
        return true;
    }

    public static bool TryReadU64LE(ReadOnlySpan<byte> d, int offset, out ulong value)
    {
        if (offset < 0 || offset + 8 > d.Length) { value = 0; return false; }
        value = 0;
        for (int i = 7; i >= 0; i--) value = (value << 8) | d[offset + i];
        return true;
    }

    /// <summary>读 16 位 BE，越界返回 0。</summary>
    public static ushort U16BE(ReadOnlySpan<byte> d, int offset) => TryReadU16BE(d, offset, out ushort v) ? v : (ushort)0;

    /// <summary>读 16 位 LE，越界返回 0。</summary>
    public static ushort U16LE(ReadOnlySpan<byte> d, int offset) => TryReadU16LE(d, offset, out ushort v) ? v : (ushort)0;

    /// <summary>读 32 位 BE，越界返回 0。</summary>
    public static uint U32BE(ReadOnlySpan<byte> d, int offset) => TryReadU32BE(d, offset, out uint v) ? v : 0;

    /// <summary>读 32 位 LE，越界返回 0。</summary>
    public static uint U32LE(ReadOnlySpan<byte> d, int offset) => TryReadU32LE(d, offset, out uint v) ? v : 0;

    /// <summary>读 64 位 BE，越界返回 0。</summary>
    public static ulong U64BE(ReadOnlySpan<byte> d, int offset) => TryReadU64BE(d, offset, out ulong v) ? v : 0;

    /// <summary>读 64 位 LE，越界返回 0。</summary>
    public static ulong U64LE(ReadOnlySpan<byte> d, int offset) => TryReadU64LE(d, offset, out ulong v) ? v : 0;

    /// <summary>读取定长 ASCII 字段（去尾部空白与 NUL）。</summary>
    public static string Ascii(ReadOnlySpan<byte> d, int offset, int length)
    {
        if (offset < 0 || offset >= d.Length || length <= 0) return string.Empty;
        int n = Math.Min(length, d.Length - offset);
        var chars = new char[n];
        for (int i = 0; i < n; i++)
        {
            byte b = d[offset + i];
            chars[i] = b is >= 0x20 and < 0x7F ? (char)b : '.';
        }
        return new string(chars).TrimEnd('.', '\0', ' ');
    }
}
