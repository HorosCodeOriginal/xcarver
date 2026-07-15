using System;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HorosCarver.Services;

namespace HorosCarver.ViewModels;

public partial class ScanOptionsViewModel : ObservableObject
{
    private readonly CarverService _carver;
    private readonly SourceViewModel _source;
    private readonly MainViewModel _main;
    private CancellationTokenSource? _scanCts;

    public ObservableCollection<string> TypeFilters { get; } = new()
    {
        "Alle (119)",
        "image",
        "document",
        "archive",
        "jpeg,pdf,sqlite",
    };

    [ObservableProperty]
    private bool _fsAwareRecovery = true;

    [ObservableProperty]
    private bool _rawCarving = true;

    [ObservableProperty]
    private bool _entropySkip;

    [ObservableProperty]
    private bool _resumeSession;

    [ObservableProperty]
    private string _selectedTypeFilter = "Alle (119)";

    [ObservableProperty]
    private int _threadCount = 4;

    [ObservableProperty]
    private string _outputDirectory = "./carved";

    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private string? _scanError;

    public ScanOptionsViewModel(CarverService carver, SourceViewModel source, MainViewModel main)
    {
        _carver = carver;
        _source = source;
        _main = main;
        _source.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(SourceViewModel.SourcePath))
                StartScanCommand.NotifyCanExecuteChanged();
        };
    }

    partial void OnFsAwareRecoveryChanged(bool value) => StartScanCommand.NotifyCanExecuteChanged();
    partial void OnRawCarvingChanged(bool value) => StartScanCommand.NotifyCanExecuteChanged();
    partial void OnIsScanningChanged(bool value)
    {
        StartScanCommand.NotifyCanExecuteChanged();
        CancelScanCommand.NotifyCanExecuteChanged();
        BrowseOutputCommand.NotifyCanExecuteChanged();
    }

    private bool CanStartScan() =>
        !IsScanning
        && !string.IsNullOrWhiteSpace(_source.SourcePath)
        && (FsAwareRecovery || RawCarving);

    private bool CanCancelScan() => IsScanning;

    [RelayCommand(CanExecute = nameof(CanStartScan))]
    private async Task StartScanAsync()
    {
        ScanError = null;
        IsScanning = true;
        _main.Results.OutputDirectory = OutputDirectory;
        _main.Results.BeginScan();
        _main.StatusText = "Scan läuft…";
        _scanCts = new CancellationTokenSource();

        try
        {
            var fsOnly = FsAwareRecovery && !RawCarving;
            var rawOnly = RawCarving && !FsAwareRecovery;
            var typeFilter = SelectedTypeFilter.StartsWith("Alle", StringComparison.Ordinal)
                ? null
                : SelectedTypeFilter;

            var exitCode = await _carver.RunAsync(
                new CarverRunOptions
                {
                    SourcePath = _source.SourcePath,
                    OutputDirectory = OutputDirectory,
                    ThreadCount = ThreadCount,
                    FsOnly = fsOnly,
                    RawOnly = rawOnly,
                    TypeFilter = typeFilter,
                    EntropySkip = EntropySkip,
                    Resume = ResumeSession,
                },
                new Progress<string>(line =>
                {
                    _main.Results.UpdateFromProgressLine(line);
                    _main.Results.AppendLog(line);
                    if (line.Contains('%') || line.Contains("Terminé") || line.Contains("RAPPORT"))
                        _main.StatusText = line.Trim();
                }),
                _scanCts.Token);

            if (_scanCts.Token.IsCancellationRequested)
            {
                _main.Results.EndScanWithoutResults();
                _main.StatusText = "Scan abgebrochen";
                return;
            }

            if (exitCode == 0)
            {
                var report = CarverReportLoader.TryLoad(OutputDirectory);
                if (report is not null)
                    _main.Results.ApplyReport(report);
                else
                    _main.Results.EndScanWithoutResults();

                _main.StatusText = $"Scan abgeschlossen → {OutputDirectory}";
            }
            else
            {
                _main.Results.EndScanWithoutResults();
                _main.StatusText = $"Scan fehlgeschlagen (Code {exitCode})";
                ScanError = $"carver.py beendet mit Exit-Code {exitCode}.";
            }
        }
        catch (OperationCanceledException)
        {
            _main.Results.EndScanWithoutResults();
            _main.StatusText = "Scan abgebrochen";
        }
        catch (Exception ex)
        {
            ScanError = ex.Message;
            _main.StatusText = "Scan-Fehler";
            _main.Results.EndScanWithoutResults();
        }
        finally
        {
            _scanCts?.Dispose();
            _scanCts = null;
            IsScanning = false;
        }
    }

    [RelayCommand(CanExecute = nameof(CanCancelScan))]
    private void CancelScan()
    {
        _main.StatusText = "Scan wird abgebrochen…";
        _scanCts?.Cancel();
    }

    [RelayCommand(CanExecute = nameof(CanBrowseOutput))]
    private async Task BrowseOutputAsync()
    {
        var window = GetMainWindow();
        if (window?.StorageProvider is null)
            return;

        var folders = await window.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = "Ausgabeordner wählen",
            AllowMultiple = false,
        });

        if (folders.Count > 0 && folders[0].TryGetLocalPath() is { } path)
            OutputDirectory = path;
    }

    private bool CanBrowseOutput() => !IsScanning;

    private static Window? GetMainWindow()
    {
        if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            return desktop.MainWindow;
        return null;
    }
}
