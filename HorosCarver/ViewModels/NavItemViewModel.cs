using CommunityToolkit.Mvvm.ComponentModel;

namespace HorosCarver.ViewModels;

public partial class NavItemViewModel : ObservableObject
{
    public required string Id { get; init; }
    public required string Label { get; init; }
    public required string IconGlyph { get; init; }

    [ObservableProperty]
    private bool _isSelected;
}
