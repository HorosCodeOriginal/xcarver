using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HorosCarver.Services;

namespace HorosCarver.ViewModels;

public partial class ResultsViewModel : ObservableObject
{
    private static readonly Regex ProgressRegex = new(@"(\d+)\s*%", RegexOptions.Compiled);
    private static readonly Regex CountRegex = new(@"(\d+)\s*✓", RegexOptions.Compiled);

    private readonly MainViewModel? _main;

    public ObservableCollection<ResultEntryViewModel> RecentFiles { get; } = new();
    public ObservableCollection<string> LogLines { get; } = new();

    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private bool _hasResults;

    [ObservableProperty]
    private string _placeholderText = "Noch keine Dateien wiederhergestellt";

    [ObservableProperty]
    private string _scanPhase = "";

    [ObservableProperty]
    private int _progressPercent;

    [ObservableProperty]
    private int _liveRecoveredCount;

    [ObservableProperty]
    private int _fsRecovered;

    [ObservableProperty]
    private int _rawRecovered;

    [ObservableProperty]
    private int _totalRecovered;

    [ObservableProperty]
    private string _summaryLine = "";

    [ObservableProperty]
    private bool _showPlaceholder = true;

    [ObservableProperty]
    private string _outputDirectory = "";

    [ObservableProperty]
    private bool _hasLogLines;

    [ObservableProperty]
    private bool _canOpenFolder;

    public ResultsViewModel(MainViewModel? main = null) => _main = main;

    partial void OnOutputDirectoryChanged(string value) =>
        CanOpenFolder = !string.IsNullOrWhiteSpace(value);

    public void AppendLog(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return;
        LogLines.Add(line);
        HasLogLines = true;
    }

    [RelayCommand]
    private void OpenOutputFolder()
    {
        if (string.IsNullOrWhiteSpace(OutputDirectory))
            return;

        var fullPath = Path.GetFullPath(OutputDirectory);
        if (!Directory.Exists(fullPath))
            Directory.CreateDirectory(fullPath);

        Process.Start(new ProcessStartInfo
        {
            FileName = "explorer.exe",
            Arguments = $"\"{fullPath}\"",
            UseShellExecute = true,
        });
    }

    [RelayCommand]
    private void OpenResultFile(ResultEntryViewModel? entry)
    {
        if (entry is null)
            return;

        var path = entry.FullPath;
        if (string.IsNullOrWhiteSpace(path))
        {
            _main?.SetStatus("Dateipfad nicht verfügbar");
            return;
        }

        if (!File.Exists(path))
        {
            _main?.SetStatus($"Datei nicht gefunden: {path}");
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = path,
                UseShellExecute = true,
            });
            _main?.SetStatus($"Geöffnet: {entry.Name}");
        }
        catch (Exception ex)
        {
            _main?.SetStatus($"Datei konnte nicht geöffnet werden: {ex.Message}");
        }
    }

    public void Reset()
    {
        IsScanning = false;
        HasResults = false;
        ScanPhase = "";
        ProgressPercent = 0;
        LiveRecoveredCount = 0;
        FsRecovered = 0;
        RawRecovered = 0;
        TotalRecovered = 0;
        SummaryLine = "";
        PlaceholderText = "Noch keine Dateien wiederhergestellt";
        RecentFiles.Clear();
        LogLines.Clear();
        HasLogLines = false;
        UpdatePlaceholderVisibility();
    }

    public void BeginScan()
    {
        Reset();
        IsScanning = true;
        ScanPhase = "Scan wird gestartet…";
        PlaceholderText = "";
        UpdatePlaceholderVisibility();
    }

    partial void OnIsScanningChanged(bool value) => UpdatePlaceholderVisibility();
    partial void OnHasResultsChanged(bool value) => UpdatePlaceholderVisibility();

    private void UpdatePlaceholderVisibility() =>
        ShowPlaceholder = !IsScanning && !HasResults;

    public void UpdateFromProgressLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return;

        if (line.Contains("[1/2]", StringComparison.Ordinal) || line.Contains("FS", StringComparison.OrdinalIgnoreCase))
            ScanPhase = "Phase 1: FS-aware Recovery";
        else if (line.Contains("[2/2]", StringComparison.Ordinal) || line.Contains("Raw carving", StringComparison.OrdinalIgnoreCase))
            ScanPhase = "Phase 2: Raw Carving";

        var pct = ProgressRegex.Match(line);
        if (pct.Success && int.TryParse(pct.Groups[1].Value, out var p))
            ProgressPercent = Math.Clamp(p, 0, 100);

        var cnt = CountRegex.Match(line);
        if (cnt.Success && int.TryParse(cnt.Groups[1].Value, out var c))
            LiveRecoveredCount = c;
    }

    public void ApplyReport(CarverReportSummary report)
    {
        FsRecovered = report.FsRecovered;
        RawRecovered = report.RawTotal;
        TotalRecovered = FsRecovered + RawRecovered;
        HasResults = TotalRecovered > 0 || report.RecentFiles.Count > 0;
        IsScanning = false;
        ProgressPercent = 100;

        var speed = report.SpeedBps > 0
            ? $"{report.SpeedBps / (1024.0 * 1024.0):F1} MB/s"
            : "—";
        SummaryLine = $"FS: {FsRecovered} · Raw: {RawRecovered} · {report.ElapsedSeconds:F1}s · {speed}";

        var outputRoot = string.IsNullOrWhiteSpace(OutputDirectory)
            ? ""
            : Path.GetFullPath(OutputDirectory);

        RecentFiles.Clear();
        foreach (var f in report.RecentFiles)
        {
            var fullPath = string.IsNullOrWhiteSpace(outputRoot)
                ? ""
                : Path.GetFullPath(Path.Combine(outputRoot, f.RelativePath));

            RecentFiles.Add(new ResultEntryViewModel
            {
                Name = f.Name,
                Path = f.RelativePath,
                FullPath = fullPath,
                Category = f.Category,
                SizeDisplay = FormatSize(f.SizeBytes),
            });
        }

        if (!HasResults)
            PlaceholderText = "Noch keine Dateien wiederhergestellt";
        UpdatePlaceholderVisibility();
    }

    public void EndScanWithoutResults()
    {
        IsScanning = false;
        if (!HasResults)
            PlaceholderText = "Noch keine Dateien wiederhergestellt";
        UpdatePlaceholderVisibility();
    }

    private static string FormatSize(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        return $"{bytes / (1024.0 * 1024.0):F1} MB";
    }
}

public partial class ResultEntryViewModel : ObservableObject
{
    [ObservableProperty]
    private string _name = "";

    [ObservableProperty]
    private string _path = "";

    [ObservableProperty]
    private string _fullPath = "";

    [ObservableProperty]
    private string _category = "";

    [ObservableProperty]
    private string _sizeDisplay = "";
}
