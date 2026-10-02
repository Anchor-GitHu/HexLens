using System.IO;
using System.Windows;

namespace HexLens.App;

/// <summary>应用入口。</summary>
public partial class App : Application
{
    /// <summary>命令行里传入的文件路径（供"用 HexLens 打开"使用）。</summary>
    public static string? StartupFile { get; private set; }

    /// <summary>启动时直接切到的视图（--view=hex|structure|stego|strings|entropy）。</summary>
    public static string? StartupView { get; private set; }

    /// <summary>界面自检报告输出路径（--smoke-test=路径）。</summary>
    public static string? SmokeTestReportPath { get; private set; }

    /// <summary>编码库自检报告输出路径（--codec-test=路径，不创建窗口）。</summary>
    public static string? CodecTestReportPath { get; private set; }

    /// <summary>启动时自动选中的区间（--select=偏移,长度；偏移支持 0x 前缀）。</summary>
    public static (int Offset, int Length)? StartupSelection { get; private set; }

    /// <summary>启动后自动打开十六进制视图的右键菜单（--demo-menu，用于核对菜单样式）。</summary>
    public static bool DemoContextMenu { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // 诊断：把收到的命令行参数落盘。排查"参数没生效导致开了主窗口"这类问题时，
        // 这是唯一能确认应用到底收到了什么的手段（GUI 进程的 stdout 常被父进程管道吞掉）。
        try
        {
            File.AppendAllText(
                Path.Combine(Path.GetTempPath(), "hexlens-args.log"),
                $"{DateTime.Now:HH:mm:ss} args=[{string.Join(" | ", e.Args)}]{Environment.NewLine}");
        }
        catch
        {
            // 诊断失败不影响主流程
        }

        foreach (string arg in e.Args)
        {
            if (arg.StartsWith("--view=", StringComparison.OrdinalIgnoreCase))
            {
                StartupView = arg["--view=".Length..].ToLowerInvariant();
                continue;
            }

            if (arg.StartsWith("--smoke-test=", StringComparison.OrdinalIgnoreCase))
            {
                SmokeTestReportPath = arg["--smoke-test=".Length..];
                continue;
            }

            if (arg.StartsWith("--codec-test=", StringComparison.OrdinalIgnoreCase))
            {
                CodecTestReportPath = arg["--codec-test=".Length..];
                continue;
            }

            // 启动即选中某段字节（配合「选中即识别」，也方便脚本化定位）
            if (arg.StartsWith("--select=", StringComparison.OrdinalIgnoreCase))
            {
                string[] parts = arg["--select=".Length..].Split(',');
                if (parts.Length == 2
                    && TryParseOffset(parts[0], out int offset)
                    && int.TryParse(parts[1].Trim(), out int length)
                    && offset >= 0 && length > 0)
                {
                    StartupSelection = (offset, length);
                }
                continue;
            }

            // 自动弹出右键菜单（临时参数，用于截图核对菜单样式）
            if (arg.Equals("--demo-menu", StringComparison.OrdinalIgnoreCase))
            {
                DemoContextMenu = true;
                continue;
            }

            // 允许用绝对路径或相对路径直接打开一个样本
            if (!arg.StartsWith('-') && File.Exists(arg) && StartupFile is null)
            {
                StartupFile = Path.GetFullPath(arg);
            }
        }

        // 编码库自检：纯逻辑校验，不需要界面。
        // 注意两点（都踩过）：
        //   ① 不能用 Shutdown()：它在 OnStartup 阶段（消息循环尚未启动）会留下"无窗口也不退出"的僵尸进程；
        //   ② 不能写 StartupUri = null：该属性会抛 ArgumentNullException（它就是靠这个崩过一次）。
        // Environment.Exit 会立即终止进程，根本走不到创建主窗口那一步。
        if (CodecTestReportPath is { } codecReport)
        {
            Environment.Exit(Diagnostics.CodecTest.Run(codecReport));
        }
    }

    /// <summary>把 "0x43F12" 或 "278290" 解析成偏移。</summary>
    private static bool TryParseOffset(string text, out int value)
    {
        text = text.Trim();
        return text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? int.TryParse(text[2..], System.Globalization.NumberStyles.HexNumber, null, out value)
            : int.TryParse(text, out value);
    }
}
