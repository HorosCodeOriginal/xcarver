using System.Text.Json.Serialization;

namespace HorosCarver.Models;

public sealed class DeviceInfo
{
    [JsonPropertyName("path")]
    public string Path { get; set; } = "";

    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("size")]
    public long Size { get; set; }

    [JsonPropertyName("removable")]
    public bool Removable { get; set; }

    [JsonPropertyName("model")]
    public string Model { get; set; } = "";

    [JsonPropertyName("fstype")]
    public string FsType { get; set; } = "";
}
