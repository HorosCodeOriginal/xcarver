using System.Linq;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using HorosCarver.ViewModels;
using HorosCarver.ViewModels.Previews;
using HorosCarver.Views;
using HorosCarver.Views.Previews;

namespace HorosCarver;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var previewArg = desktop.Args?.FirstOrDefault(a => a.StartsWith("--preview"));
            if (previewArg is not null)
            {
                desktop.MainWindow = previewArg switch
                {
                    "--preview-source" => new SourcePanelPreview
                    {
                        DataContext = new SourcePanelPreviewViewModel(),
                    },
                    "--preview-scan" => new ScanOptionsPanelPreview
                    {
                        DataContext = new ScanOptionsPanelPreviewViewModel(),
                    },
                    "--preview-results" => new ResultsPanelPreview
                    {
                        DataContext = new ResultsPanelPreviewViewModel(),
                    },
                    _ => new ShellRegionPreview
                    {
                        DataContext = new ShellRegionPreviewViewModel(),
                    },
                };
            }
            else
            {
                desktop.MainWindow = new MainWindow
                {
                    DataContext = new MainViewModel(),
                };
            }
        }

        base.OnFrameworkInitializationCompleted();
    }
}
