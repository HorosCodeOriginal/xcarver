using System;
using System.Collections.ObjectModel;
using System.Linq;
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

public partial class SourceViewModel : ObservableObject
{
    private readonly CarverService _carver;

    public ObservableCollection<string> SourceTypes { get; } = new()
    {
        "Physisches Laufwerk",
        "Image-Datei (.dd / .img / .bin)",
        "EnCase E01",
    };

    public ObservableCollection<DeviceItemViewModel> Devices { get; } = new();

    [ObservableProperty]
    private string _sourcePath = "";

    [ObservableProperty]
    private string _selectedSourceType = "Physisches Laufwerk";

    [ObservableProperty]
    private string _dropHint = "Image oder Device hier ablegen";

    [ObservableProperty]
    private DeviceItemViewModel? _selectedDevice;

    [ObservableProperty]
    private bool _isLoadingDevices;

    [ObservableProperty]
    private string? _deviceLoadError;

    public bool IsPhysicalDevice =>
        SelectedSourceType == "Physisches Laufwerk";

    public SourceViewModel(CarverService carver)
    {
        _carver = carver;
    }

    partial void OnSelectedSourceTypeChanged(string value)
    {
        OnPropertyChanged(nameof(IsPhysicalDevice));
        if (IsPhysicalDevice && Devices.Count == 0)
            _ = RefreshDevicesCommand.ExecuteAsync(null);
    }

    partial void OnSelectedDeviceChanged(DeviceItemViewModel? value)
    {
        if (value is not null)
            SourcePath = value.Path;
    }

    [RelayCommand]
    private async Task RefreshDevicesAsync()
    {
        if (!IsPhysicalDevice)
            return;

        IsLoadingDevices = true;
        DeviceLoadError = null;
        Devices.Clear();

        try
        {
            var list = await _carver.ListDevicesAsync();
            foreach (var d in list)
            {
                Devices.Add(new DeviceItemViewModel
                {
                    Path = d.Path,
                    DisplayName = FormatDeviceLabel(d),
                });
            }

            if (Devices.Count == 0)
            {
                DeviceLoadError = "Keine Geräte gefunden (Admin-Rechte nötig?).";
                return;
            }

            SelectedDevice = Devices.FirstOrDefault(d => d.Path == SourcePath)
                             ?? Devices[0];
        }
        catch (Exception ex)
        {
            DeviceLoadError = ex.Message;
        }
        finally
        {
            IsLoadingDevices = false;
        }
    }

    [RelayCommand]
    private async Task BrowseAsync()
    {
        var window = GetMainWindow();
        if (window?.StorageProvider is null)
            return;

        if (IsPhysicalDevice)
        {
            await RefreshDevicesCommand.ExecuteAsync(null);
            return;
        }

        var filters = SelectedSourceType.Contains("E01")
            ? new[] { new FilePickerFileType("EnCase") { Patterns = new[] { "*.e01", "*.E01" } } }
            : new[]
            {
                new FilePickerFileType("Disk Images")
                {
                    Patterns = new[] { "*.dd", "*.img", "*.bin", "*.raw" },
                },
            };

        var files = await window.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Quelle auswählen",
            AllowMultiple = false,
            FileTypeFilter = filters,
        });

        if (files.Count > 0 && files[0].TryGetLocalPath() is { } path)
            SourcePath = path;
    }

    public void SetPathFromDrop(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return;

        SourcePath = path;
        if (IsPhysicalDevice)
        {
            SelectedDevice = Devices.FirstOrDefault(d =>
                string.Equals(d.Path, path, StringComparison.OrdinalIgnoreCase));
        }
    }

    private static string FormatDeviceLabel(Models.DeviceInfo d)
    {
        var size = FormatSize(d.Size);
        var model = string.IsNullOrWhiteSpace(d.Model) ? "Unbekannt" : d.Model.Trim();
        var fs = string.IsNullOrWhiteSpace(d.FsType) ? "—" : d.FsType;
        return $"{model} ({size}) · {fs} · {d.Path}";
    }

    private static string FormatSize(long bytes)
    {
        if (bytes <= 0) return "0 B";
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double v = bytes;
        var i = 0;
        while (v >= 1024 && i < units.Length - 1)
        {
            v /= 1024;
            i++;
        }
        return $"{v:0.#} {units[i]}";
    }

    private static Window? GetMainWindow()
    {
        if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            return desktop.MainWindow;
        return null;
    }
}
