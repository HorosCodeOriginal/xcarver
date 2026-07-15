using HorosCarver.ViewModels;

namespace HorosCarver.ViewModels.Previews;

public class ShellRegionPreviewViewModel
{
    public SidebarViewModel Sidebar { get; } = new();

    public string StatusText { get; } = "Bereit | HorosCode C-Scanner | 119 Signaturen";
}
