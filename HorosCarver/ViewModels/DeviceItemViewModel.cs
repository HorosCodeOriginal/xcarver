namespace HorosCarver.ViewModels;

public class DeviceItemViewModel
{
    public required string Path { get; init; }
    public required string DisplayName { get; init; }

    public override string ToString() => DisplayName;
}
