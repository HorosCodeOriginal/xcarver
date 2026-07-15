using HorosCarver.Services;
using HorosCarver.ViewModels;

namespace HorosCarver.ViewModels.Previews;

public class SourcePanelPreviewViewModel
{
    public SourceViewModel Source { get; } = new(new CarverService())
    {
        SourcePath = @"D:\Evidence\usb_image.dd",
    };
}
