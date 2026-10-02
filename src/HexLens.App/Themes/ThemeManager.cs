using System.Windows;

namespace HexLens.App.Themes;

/// <summary>
/// 主题切换：把 Application.Resources 的第一份合并字典（令牌）整体换掉，
/// 所有用 DynamicResource 引用的颜色会即时更新，无需重启。
/// </summary>
public static class ThemeManager
{
    private static readonly Uri LightUri = new("Themes/Light.xaml", UriKind.Relative);
    private static readonly Uri DarkUri = new("Themes/Dark.xaml", UriKind.Relative);

    /// <summary>当前是否为暗色主题。</summary>
    public static bool IsDark { get; private set; }

    /// <summary>主题变化事件。</summary>
    public static event EventHandler? ThemeChanged;

    /// <summary>应用指定主题。</summary>
    public static void Apply(bool dark)
    {
        if (Application.Current is null) return;

        var dictionary = new ResourceDictionary { Source = dark ? DarkUri : LightUri };
        var merged = Application.Current.Resources.MergedDictionaries;

        if (merged.Count == 0) merged.Add(dictionary);
        else merged[0] = dictionary;

        IsDark = dark;
        ThemeChanged?.Invoke(null, EventArgs.Empty);
    }

    /// <summary>在明暗之间切换。</summary>
    public static void Toggle() => Apply(!IsDark);
}
