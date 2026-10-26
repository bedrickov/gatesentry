using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using GateSentry.Core.Models;

namespace GateSentry.Core.Formatters;

public static class SarifFormatter
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public static string GenerateSarif(ScanReport report)
    {
        var root = new JsonObject
        {
            ["$schema"] = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            ["version"] = "2.1.0"
        };

        var runs = new JsonArray();
        var run = new JsonObject();

        var tool = new JsonObject
        {
            ["driver"] = new JsonObject
            {
                ["name"] = "GateSentry",
                ["version"] = "1.0.0",
                ["informationUri"] = "https://github.com/nikit/GateSentry",
                ["rules"] = new JsonArray()
            }
        };

        var results = new JsonArray();

        foreach (var finding in report.Findings)
        {
            var result = new JsonObject
            {
                ["ruleId"] = finding.RuleId,
                ["level"] = MapSeverityToSarifLevel(finding.Severity),
                ["message"] = new JsonObject
                {
                    ["text"] = $"{finding.RuleName}: {finding.Description}"
                },
                ["locations"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["physicalLocation"] = new JsonObject
                        {
                            ["artifactLocation"] = new JsonObject
                            {
                                ["uri"] = finding.FilePath.Replace('\\', '/')
                            },
                            ["region"] = new JsonObject
                            {
                                ["startLine"] = finding.Location.LineNumber,
                                ["startColumn"] = finding.Location.ColumnStart,
                                ["endColumn"] = finding.Location.ColumnEnd,
                                ["snippet"] = new JsonObject
                                {
                                    ["text"] = finding.Location.RedactedContent
                                }
                            }
                        }
                    }
                },
                ["properties"] = new JsonObject
                {
                    ["fingerprint"] = finding.Fingerprint,
                    ["category"] = finding.Category.ToString(),
                    ["remediation"] = finding.Remediation ?? string.Empty
                }
            };

            results.Add(result);
        }

        run["tool"] = tool;
        run["results"] = results;
        runs.Add(run);
        root["runs"] = runs;

        return root.ToJsonString(JsonOpts);
    }

    private static string MapSeverityToSarifLevel(SeverityLevel severity) => severity switch
    {
        SeverityLevel.Critical or SeverityLevel.High => "error",
        SeverityLevel.Medium => "warning",
        SeverityLevel.Low or SeverityLevel.Info => "note",
        _ => "none"
    };
}
