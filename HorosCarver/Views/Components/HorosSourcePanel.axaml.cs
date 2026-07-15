using System.Linq;
using Avalonia.Controls;
using Avalonia.Input;
using HorosCarver.ViewModels;

namespace HorosCarver.Views.Components;

public partial class HorosSourcePanel : UserControl
{
    public HorosSourcePanel()
    {
        InitializeComponent();
    }

    private void OnDragOver(object? sender, DragEventArgs e)
    {
        e.DragEffects = e.DataTransfer.Contains(DataFormat.File)
            ? DragDropEffects.Copy
            : DragDropEffects.None;
    }

    private void OnDrop(object? sender, DragEventArgs e)
    {
        if (DataContext is not SourceViewModel vm)
            return;

        if (!e.DataTransfer.Contains(DataFormat.File))
            return;

        var files = e.DataTransfer.TryGetFiles();
        if (files is null || files.Length == 0)
            return;

        var file = files[0];
        var path = file.Path.LocalPath;
        if (!string.IsNullOrWhiteSpace(path))
            vm.SetPathFromDrop(path);
    }
}
