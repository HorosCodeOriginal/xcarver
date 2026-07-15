using System;
using System.Collections.Specialized;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;
using HorosCarver.ViewModels;

namespace HorosCarver.Views.Components;

public partial class HorosResultsPanel : UserControl
{
    private ScrollViewer? _logScrollViewer;
    private ResultsViewModel? _currentVm;

    public HorosResultsPanel()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object? sender, EventArgs e)
    {
        if (_currentVm is not null)
            _currentVm.LogLines.CollectionChanged -= OnLogLinesChanged;

        _currentVm = DataContext as ResultsViewModel;

        if (_currentVm is not null)
            _currentVm.LogLines.CollectionChanged += OnLogLinesChanged;
    }

    private void OnLogLinesChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        _logScrollViewer ??= this.FindControl<ScrollViewer>("LogScrollViewer");
        if (_logScrollViewer is null)
            return;

        Dispatcher.UIThread.Post(() => _logScrollViewer.ScrollToEnd(),
            DispatcherPriority.Background);
    }

    private void OnResultItemDoubleTapped(object? sender, TappedEventArgs e)
    {
        if (sender is not Control { DataContext: ResultEntryViewModel entry })
            return;

        if (DataContext is ResultsViewModel vm)
            vm.OpenResultFileCommand.Execute(entry);
    }

    private void OnResultItemKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter && e.Key != Key.Space)
            return;

        if (sender is not Control { DataContext: ResultEntryViewModel entry })
            return;

        if (DataContext is ResultsViewModel vm)
            vm.OpenResultFileCommand.Execute(entry);

        e.Handled = true;
    }
}
