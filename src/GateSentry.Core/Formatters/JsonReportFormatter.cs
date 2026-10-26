using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using GateSentry.Core.Models;

namespace GateSentry.Core.Formatters;

public static class JsonReportFormatter
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new JsonStringEnumConverter() }
    };

    public static string Format(ScanReport report)
    {
        return JsonSerializer.Serialize(report, JsonOpts);
    }
}
