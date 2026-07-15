using System.Reflection;
using CommunityToolkit.Mvvm.ComponentModel;
using HorosCarver.Services;

namespace HorosCarver.ViewModels;

public partial class MainViewModel : ViewModelBase
{
    private readonly CarverService _carver = new();

    public SidebarViewModel Sidebar { get; } = new();
    public SourceViewModel Source { get; }
    public ResultsViewModel Results { get; }
    public ScanOptionsViewModel Scan { get; }

    [ObservableProperty]
    private string _statusText = "Bereit | HorosCode C-Scanner | 119 Signaturen";

    public string SelectedNavId => Sidebar.SelectedItem?.Id ?? "source";

    public bool ShowSourcePanel => SelectedNavId is "source" or "scan";

    public bool ShowScanPanel => SelectedNavId is "scan";

    public bool ShowResultsHint => SelectedNavId is "results";

    public bool ShowReportPanel => SelectedNavId is "report";

    public bool ShowSettingsPanel => SelectedNavId is "settings";

    public string AppVersion =>
        Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0";

    public MainViewModel()
    {
        Source = new SourceViewModel(_carver);
        Results = new ResultsViewModel(this);
        Scan = new ScanOptionsViewModel(_carver, Source, this);

        Sidebar.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(SidebarViewModel.SelectedItem))
                NotifyNavigationChanged();
        };
    }

    public void SetStatus(string message)
    {
        if (!string.IsNullOrWhiteSpace(message))
            StatusText = message;
    }

    private void NotifyNavigationChanged()
    {
        OnPropertyChanged(nameof(SelectedNavId));
        OnPropertyChanged(nameof(ShowSourcePanel));
        OnPropertyChanged(nameof(ShowScanPanel));
        OnPropertyChanged(nameof(ShowResultsHint));
        OnPropertyChanged(nameof(ShowReportPanel));
        OnPropertyChanged(nameof(ShowSettingsPanel));
    }
}
