using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;

namespace HexLens.App.Controls;

/// <summary>
/// 主题化提示框 —— 用来替代系统的 <see cref="MessageBox"/>。
///
/// 为什么不用 MessageBox：它是方角灰白、系统字体的原生窗口，和这套纸感界面是两套语言；
/// 而且样式不跟随应用主题，暗色模式下弹出来格外刺眼。
/// 这里全部走主题令牌（PaperBrush / InkBrush / BorderSubtleBrush…），明暗自动跟随。
/// </summary>
public partial class ThemedDialog : Window
{
    /// <summary>超过这个长度就显示「复制」按钮 —— 长路径、异常信息通常需要整段拷走。</summary>
    private const int CopyButtonThreshold = 40;

    private ThemedDialog()
    {
        InitializeComponent();

        // 窗口句柄要等源初始化之后才有，圆角得在这时候设置
        SourceInitialized += (_, _) => ApplyRoundedCorners();

        // 无边框窗口：自己处理 Esc 关闭
        PreviewKeyDown += (_, e) =>
        {
            if (e.Key == Key.Escape) Close();
        };
    }

    /// <summary>
    /// 让系统为无边框窗口画圆角，和主窗口保持一致。
    ///
    /// 不走 WPF 的 <c>AllowsTransparency="True"</c> + <c>Border.CornerRadius</c> 那条路：
    /// 那会换来真透明（圆角+投影都好看），但会让**整个窗口掉到软件渲染** —— 不划算。
    /// DWM 圆角是系统合成器画的，零成本。
    /// </summary>
    private void ApplyRoundedCorners()
    {
        try
        {
            IntPtr handle = new WindowInteropHelper(this).Handle;
            int preference = 2;   // DWMWCP_ROUND
            _ = DwmSetWindowAttribute(handle, 33, ref preference, sizeof(int));
        }
        catch
        {
            // 非 Win11 或 dwmapi 不可用时退化为直角窗口，不影响功能
        }
    }

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    /// <summary>显示一条警告。</summary>
    public static void ShowWarning(string title, string message)
        => Show(title, message, warning: true);

    /// <summary>显示一条普通信息。</summary>
    public static void ShowInfo(string title, string message)
        => Show(title, message, warning: false);

    /// <summary>
    /// 二选一询问：返回 <c>true</c> = 用户点了主按钮（<paramref name="primaryText"/>），
    /// <c>false</c> = 点了次按钮或关窗（次按钮默认是"取消"，会被当成取消）。
    ///
    /// 用途：「这个文件要以只读方式打开还是编辑方式打开」这类问题。
    /// 系统 MessageBox 也能问，但那样又冒出一个灰白方框，和界面不是一套语言。
    /// </summary>
    public static bool Ask(string title, string message, string primaryText, string secondaryText)
    {
        var dialog = new ThemedDialog();
        Prepare(dialog, title, message, warning: false);

        dialog.OkButton.Content = primaryText;
        dialog.AltButton.Content = secondaryText;
        dialog.AltButton.Visibility = Visibility.Visible;
        dialog.ShowDialog();

        return dialog._chosePrimary;
    }

    /// <summary>用户是否点了主按钮（ShowDialog 返回后读取）。</summary>
    private bool _chosePrimary;

    private static void Show(string title, string message, bool warning)
    {
        var dialog = new ThemedDialog();
        Prepare(dialog, title, message, warning);
        dialog.ShowDialog();
    }

    /// <summary>两个入口共用的准备逻辑：归属、位置、文案、复制按钮。</summary>
    private static void Prepare(ThemedDialog dialog, string title, string message, bool warning)
    {
        // 跟着主窗口走：既是模态归属，也保证主题令牌能沿着同一棵资源树解析
        Window? owner = Application.Current?.MainWindow;
        if (owner is not null && !ReferenceEquals(owner, dialog) && owner.IsLoaded)
        {
            dialog.Owner = owner;
            dialog.WindowStartupLocation = WindowStartupLocation.CenterOwner;
        }
        else
        {
            dialog.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        }

        dialog.TitleText.Text = warning ? $"⚠  {title}" : title;
        dialog.BodyText.Text = message;
        dialog.CopyButton.Visibility = message.Length > CopyButtonThreshold
            ? Visibility.Visible
            : Visibility.Collapsed;
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        _chosePrimary = true;
        Close();
    }

    private void Alt_Click(object sender, RoutedEventArgs e)
    {
        _chosePrimary = false;
        Close();
    }

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(BodyText.Text);
        }
        catch
        {
            // 剪贴板被别的进程占用时忽略 —— 复制失败不该再弹一个错误框
        }
    }
}
