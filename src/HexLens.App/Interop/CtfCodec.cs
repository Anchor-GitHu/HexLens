using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace HexLens.App.Interop;

/// <summary>一条编码识别建议。</summary>
public sealed record MagicSuggestion(string Algorithm, int Score, string Reason, string Preview)
{
    /// <summary>置信度比例（用于进度条）。</summary>
    public double ScoreRatio => Math.Clamp(Score / 100.0, 0, 1);

    /// <summary>置信度文本。</summary>
    public string ScoreText => $"{Score}%";
}

/// <summary>编码算法条目。</summary>
public sealed record CodecAlgorithm(string Name, string Category, string Help, bool Reversible, bool NeedsParameter);

/// <summary>
/// ctfcodec.dll 的 P/Invoke 封装（隔壁 Coding\ctfcodec 的 CTF 编码库，纯 C ABI）。
///
/// 为什么复用它：那套库已有 127 个编码算法、启发式识别与往返自检，
/// 在 HexLens 里重写一遍纯属浪费。这里只做薄封装 + 降级处理：
/// DLL 缺失或调用出错时返回空结果，绝不因为编码功能影响十六进制分析与隐写检测。
/// </summary>
public static class CtfCodec
{
    private const string Library = "ctfcodec.dll";

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr ctf_version();

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, EntryPoint = "ctf_magic")]
    private static extern IntPtr ctf_magic_native(byte[] utf8Text);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, EntryPoint = "ctf_decode")]
    private static extern int ctf_decode_native(
        string algorithm,
        byte[] input,
        UIntPtr inputLength,
        string? parameters,
        out IntPtr output,
        out UIntPtr outputLength);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, EntryPoint = "ctf_encode")]
    private static extern int ctf_encode_native(
        string algorithm,
        byte[] input,
        UIntPtr inputLength,
        string? parameters,
        out IntPtr output,
        out UIntPtr outputLength);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern void ctf_free(IntPtr pointer);

    // 算法清单刻意**不用** ctf_algo_list_json()：
    // 该导出的 JSON 里存在非法转义（实测 'X' is an invalid escapable character，BytePositionInLine≈3166），
    // System.Text.Json 会直接拒绝解析。逐项 API 更稳，也不依赖那段有问题的字符串拼装。
    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int ctf_algo_count();

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr ctf_algo_name(int index);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr ctf_algo_category(int index);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr ctf_algo_help(int index);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int ctf_algo_reversible(int index);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int ctf_algo_needs_param(int index);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr ctf_last_error();

    static CtfCodec()
    {
        try
        {
            IntPtr pointer = ctf_version();
            Version = pointer == IntPtr.Zero ? "未知" : Marshal.PtrToStringAnsi(pointer) ?? "未知";
            IsAvailable = true;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            // 典型原因：DLL 未随程序拷贝、32/64 位不匹配
            IsAvailable = false;
            Version = "不可用";
            UnavailableReason = ex switch
            {
                DllNotFoundException => "未找到 ctfcodec.dll（应与 HexLens.App.exe 同目录）",
                BadImageFormatException => "ctfcodec.dll 位数与进程不匹配（需要 x64）",
                _ => "ctfcodec.dll 缺少预期的导出函数",
            };
        }
    }

    /// <summary>编码库是否可用。</summary>
    public static bool IsAvailable { get; }

    /// <summary>库版本（不可用时为"不可用"）。</summary>
    public static string Version { get; }

    /// <summary>不可用原因（可用时为空）。</summary>
    public static string UnavailableReason { get; } = string.Empty;

    /// <summary>最近一次调用失败的原因。</summary>
    public static string LastError
    {
        get
        {
            if (!IsAvailable) return UnavailableReason;
            try
            {
                IntPtr pointer = ctf_last_error();
                return pointer == IntPtr.Zero ? string.Empty : Marshal.PtrToStringUTF8(pointer) ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }
    }

    /// <summary>
    /// 最近一次托管侧失败的原因（JSON 解析等）。
    /// 存在的意义：静默 catch 会让"返回空列表"这种故障完全无从排查（这个坑已经踩过一次）。
    /// </summary>
    public static string LastDiagnostic { get; private set; } = string.Empty;

    /// <summary>
    /// 对一段**文本**做编码识别打分，返回按可能性排序的建议。
    /// 注意：底层接口是 NUL 结尾字符串，因此含 0x00 的二进制数据请先截断。
    /// </summary>
    public static List<MagicSuggestion> Suggest(string text)
    {
        if (!IsAvailable || string.IsNullOrEmpty(text)) return [];

        IntPtr pointer = IntPtr.Zero;
        try
        {
            byte[] utf8 = Encoding.UTF8.GetBytes(text);
            byte[] buffer = new byte[utf8.Length + 1];      // 末尾留 NUL
            utf8.CopyTo(buffer, 0);

            pointer = ctf_magic_native(buffer);
            if (pointer == IntPtr.Zero) return [];

            string json = Marshal.PtrToStringUTF8(pointer) ?? string.Empty;
            return ParseSuggestions(json);
        }
        catch
        {
            return [];
        }
        finally
        {
            if (pointer != IntPtr.Zero) ctf_free(pointer);
        }
    }

    /// <summary>用指定算法解码；失败返回 null。</summary>
    public static byte[]? Decode(string algorithm, byte[] data, string? parameters = null)
        => Invoke(ctf_decode_native, algorithm, data, parameters);

    /// <summary>用指定算法编码；失败返回 null。</summary>
    public static byte[]? Encode(string algorithm, byte[] data, string? parameters = null)
        => Invoke(ctf_encode_native, algorithm, data, parameters);

    /// <summary>取出全部算法清单（逐项读取，绕开有非法转义的 list_json 导出）。</summary>
    public static List<CodecAlgorithm> Algorithms()
    {
        var list = new List<CodecAlgorithm>();
        LastDiagnostic = string.Empty;
        if (!IsAvailable) return list;

        try
        {
            int count = ctf_algo_count();
            for (int i = 0; i < count; i++)
            {
                list.Add(new CodecAlgorithm(
                    ReadUtf8(ctf_algo_name(i)),
                    ReadUtf8(ctf_algo_category(i)),
                    ReadUtf8(ctf_algo_help(i)),
                    ctf_algo_reversible(i) != 0,
                    ctf_algo_needs_param(i) != 0));
            }

            if (list.Count == 0) LastDiagnostic = $"ctf_algo_count() 返回 {count}";
        }
        catch (Exception ex)
        {
            // 不再静默吞异常：正是它让"清单 0 种"这个故障一度无从排查
            LastDiagnostic = $"{ex.GetType().Name}: {ex.Message}";
        }
        return list;
    }

    private static string ReadUtf8(IntPtr pointer)
        => pointer == IntPtr.Zero ? string.Empty : Marshal.PtrToStringUTF8(pointer) ?? string.Empty;

    private delegate int CodecInvoke(
        string algorithm,
        byte[] input,
        UIntPtr inputLength,
        string? parameters,
        out IntPtr output,
        out UIntPtr outputLength);

    private static byte[]? Invoke(CodecInvoke native, string algorithm, byte[] data, string? parameters)
    {
        if (!IsAvailable || string.IsNullOrEmpty(algorithm) || data.Length == 0) return null;

        IntPtr output = IntPtr.Zero;
        try
        {
            int code = native(algorithm, data, (UIntPtr)data.Length, parameters, out output, out UIntPtr length);
            if (code != 0 || output == IntPtr.Zero) return null;

            int size = checked((int)length);
            if (size <= 0) return [];

            var result = new byte[size];
            Marshal.Copy(output, result, 0, size);
            return result;
        }
        catch
        {
            return null;
        }
        finally
        {
            if (output != IntPtr.Zero) ctf_free(output);
        }
    }

    private static List<MagicSuggestion> ParseSuggestions(string json)
    {
        var list = new List<MagicSuggestion>();
        if (string.IsNullOrWhiteSpace(json)) return list;

        try
        {
            using JsonDocument document = JsonDocument.Parse(json);
            foreach (JsonElement element in document.RootElement.EnumerateArray())
            {
                list.Add(new MagicSuggestion(
                    GetString(element, "alg"),
                    GetInt(element, "score"),
                    GetString(element, "reason"),
                    GetString(element, "preview")));
            }
        }
        catch
        {
            // 返回体异常时按"没有建议"处理
        }
        return list;
    }

    private static string GetString(JsonElement element, string name)
        => element.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? string.Empty
            : string.Empty;

    private static int GetInt(JsonElement element, string name)
        => element.TryGetProperty(name, out JsonElement value) && value.TryGetInt32(out int number) ? number : 0;

    private static bool GetBool(JsonElement element, string name)
        => element.TryGetProperty(name, out JsonElement value) && value.ValueKind is JsonValueKind.True;
}
