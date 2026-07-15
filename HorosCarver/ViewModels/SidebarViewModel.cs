using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace HorosCarver.ViewModels;

public partial class SidebarViewModel : ObservableObject
{
    public ObservableCollection<NavItemViewModel> Items { get; } = new()
    {
        new NavItemViewModel { Id = "source", Label = "Quelle", IconGlyph = "⌂", IsSelected = true },
        new NavItemViewModel { Id = "scan", Label = "Scan", IconGlyph = "◎" },
        new NavItemViewModel { Id = "results", Label = "Ergebnisse", IconGlyph = "☰" },
        new NavItemViewModel { Id = "report", Label = "Bericht", IconGlyph = "▤" },
        new NavItemViewModel { Id = "settings", Label = "Einstellungen", IconGlyph = "⚙" },
    };

    [ObservableProperty]
    private NavItemViewModel? _selectedItem;

    public SidebarViewModel()
    {
        SelectedItem = Items[0];
    }

    [RelayCommand]
    private void SelectNav(NavItemViewModel? item)
    {
        if (item is null)
            return;

        foreach (var nav in Items)
            nav.IsSelected = false;

        item.IsSelected = true;
        SelectedItem = item;
    }
}
