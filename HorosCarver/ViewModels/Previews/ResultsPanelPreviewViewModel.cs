using HorosCarver.ViewModels;

namespace HorosCarver.ViewModels.Previews;

public class ResultsPanelPreviewViewModel
{
    public ResultsViewModel Results { get; } = CreateSampleResults();

    private static ResultsViewModel CreateSampleResults()
    {
        var vm = new ResultsViewModel();
        vm.ApplyReport(new Services.CarverReportSummary
        {
            FsRecovered = 2,
            RawTotal = 3,
            ElapsedSeconds = 0.4,
            SpeedBps = 324_800,
            RecentFiles =
            [
                new Services.RecoveredFileInfo
                {
                    Name = "jpeg_0000000000001000_00001.jpg",
                    RelativePath = @"raw\jpeg\jpeg_0000000000001000_00001.jpg",
                    SizeBytes = 236,
                    Category = "JPEG",
                },
                new Services.RecoveredFileInfo
                {
                    Name = "png_00000000000030ec_00001.png",
                    RelativePath = @"raw\png\png_00000000000030ec_00001.png",
                    SizeBytes = 68,
                    Category = "PNG",
                },
            ],
        });
        return vm;
    }
}
