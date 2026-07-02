using System.Globalization;
using System.Text;
using AES.WinForms.Models;

namespace AES.WinForms.Services;

public sealed class BenchmarkCsvService
{
    public string CreateCsv(BenchmarkSession session)
    {
        var builder = new StringBuilder();
        var environmentInfo = session.EnvironmentInfo ?? new BenchmarkEnvironmentInfo();

        AppendMetadata(builder, "SessionId", session.SessionId.ToString());
        AppendMetadata(builder, "CreatedUtc", session.CreatedUtc.ToString("O", CultureInfo.InvariantCulture));
        AppendMetadata(builder, "Algorithm", session.Request.Algorithm.ToString());
        AppendMetadata(builder, "Padding", session.Request.Algorithm == CryptoAlgorithm.Gcm ? "N/A" : session.Request.Padding.ToString());
        AppendMetadata(builder, "KeySizeBits", session.Request.KeySizeBits.ToString(CultureInfo.InvariantCulture));
        AppendMetadata(builder, "DataSizeMegabytes", session.Request.DataSizeMegabytes.ToString(CultureInfo.InvariantCulture));
        AppendMetadata(builder, "IterationCount", session.Request.IterationCount.ToString(CultureInfo.InvariantCulture));
        AppendMetadata(builder, "WarmupBeforeRun", session.Request.WarmupBeforeRun.ToString(CultureInfo.InvariantCulture));
        AppendMetadata(builder, "Password", session.Request.Password);
        AppendMetadata(builder, "SaltBase64", session.SaltBase64);
        AppendMetadata(builder, "Iv16Base64", session.Iv16Base64);
        AppendMetadata(builder, "Iv12Base64", session.Iv12Base64);
        AppendMetadata(builder, "AadBase64", session.AadBase64);
        AppendMetadata(builder, "EnvironmentDescription", session.EnvironmentDescription);
        AppendMetadata(builder, "FrameworkDescription", environmentInfo.FrameworkDescription);
        AppendMetadata(builder, "OperatingSystemDescription", environmentInfo.OperatingSystemDescription);
        AppendMetadata(builder, "WindowsVersion", environmentInfo.WindowsVersion);
        AppendMetadata(builder, "WindowsBuild", environmentInfo.WindowsBuild);
        AppendMetadata(builder, "ProcessArchitecture", environmentInfo.ProcessArchitecture);
        AppendMetadata(builder, "BuildArchitecture", environmentInfo.BuildArchitecture);
        AppendMetadata(builder, "LogicalProcessorCount", environmentInfo.LogicalProcessorCount);
        AppendMetadata(builder, "ProcessorName", environmentInfo.ProcessorName);
        AppendMetadata(builder, "ProcessorCoreCount", environmentInfo.ProcessorCoreCount);
        AppendMetadata(builder, "ProcessorLogicalCoreCount", environmentInfo.ProcessorLogicalCoreCount);
        AppendMetadata(builder, "ProcessorMaxClockMHz", environmentInfo.ProcessorMaxClockMHz);
        AppendMetadata(builder, "GpuName", environmentInfo.GpuName);
        AppendMetadata(builder, "MotherboardName", environmentInfo.MotherboardName);
        AppendMetadata(builder, "PowerSource", environmentInfo.PowerSource);
        AppendMetadata(builder, "WindowsPowerPlan", environmentInfo.WindowsPowerPlan);
        AppendMetadata(builder, "RamTotal", environmentInfo.RamTotal);
        AppendMetadata(builder, "RamModules", environmentInfo.RamModules);
        AppendMetadata(builder, "OpenClPlatformName", environmentInfo.OpenClPlatformName);
        AppendMetadata(builder, "OpenClPlatformVersion", environmentInfo.OpenClPlatformVersion);
        AppendMetadata(builder, "OpenClDeviceName", environmentInfo.OpenClDeviceName);
        AppendMetadata(builder, "OpenClDeviceVersion", environmentInfo.OpenClDeviceVersion);
        AppendMetadata(builder, "OpenClCVersion", environmentInfo.OpenClCVersion);
        AppendMetadata(builder, "OpenClInfoStatus", environmentInfo.OpenClInfoStatus);
        AppendMetadata(builder, "Notes", session.Notes);
        builder.AppendLine();

        builder.AppendLine("TimestampUtc,Iteration,Engine,Direction,Algorithm,Padding,KeySizeBits,InputBytes,OutputBytes,ElapsedMilliseconds,ThroughputMegabytesPerSecond,Succeeded,SpeedupVsSequentialNativeCpu,ManagedReferenceRatio,Note");

        foreach (var row in session.Rows)
        {
            builder.AppendLine(string.Join(',',
                Escape(row.TimestampUtc.ToString("O", CultureInfo.InvariantCulture)),
                Escape(row.Iteration.ToString(CultureInfo.InvariantCulture)),
                Escape(row.Engine.ToString()),
                Escape(row.Direction.ToString()),
                Escape(row.Algorithm.ToString()),
                Escape(row.Padding.ToString()),
                Escape(row.KeySizeBits.ToString(CultureInfo.InvariantCulture)),
                Escape(row.InputBytes.ToString(CultureInfo.InvariantCulture)),
                Escape(row.OutputBytes.ToString(CultureInfo.InvariantCulture)),
                Escape(row.ElapsedMilliseconds.ToString("F6", CultureInfo.InvariantCulture)),
                Escape(row.ThroughputMegabytesPerSecond.ToString("F6", CultureInfo.InvariantCulture)),
                Escape(row.Succeeded.ToString(CultureInfo.InvariantCulture)),
                Escape(row.RelativeSpeedupVsNativeCpu?.ToString("F6", CultureInfo.InvariantCulture) ?? string.Empty),
                Escape(row.RelativeSpeedupVsManagedAes?.ToString("F6", CultureInfo.InvariantCulture) ?? string.Empty),
                Escape(row.Note)));
        }

        return builder.ToString();
    }

    public BenchmarkSession ParseCsv(string csvContent)
    {
        using var reader = new StringReader(csvContent);
        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var rows = new List<BenchmarkResultRow>();
        string? line;
        var inDataSection = false;

        while ((line = reader.ReadLine()) is not null)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            if (!inDataSection && line.StartsWith("#", StringComparison.Ordinal))
            {
                var metadataLine = line[1..];
                var separatorIndex = metadataLine.IndexOf(',');
                if (separatorIndex > 0)
                {
                    var key = metadataLine[..separatorIndex];
                    var value = Unescape(metadataLine[(separatorIndex + 1)..]);
                    metadata[key] = value;
                }

                continue;
            }

            if (!inDataSection)
            {
                inDataSection = true;
                continue;
            }

            var fields = SplitCsvLine(line);
            if (fields.Count < 15)
            {
                continue;
            }

            rows.Add(new BenchmarkResultRow
            {
                SessionId = Guid.Parse(metadata["SessionId"]),
                TimestampUtc = DateTimeOffset.Parse(fields[0], CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                Iteration = int.Parse(fields[1], CultureInfo.InvariantCulture),
                Engine = Enum.Parse<CryptoEngine>(fields[2], true),
                Direction = Enum.Parse<BenchmarkDirection>(fields[3], true),
                Algorithm = Enum.Parse<CryptoAlgorithm>(fields[4], true),
                Padding = Enum.Parse<CryptoPaddingMode>(fields[5], true),
                KeySizeBits = int.Parse(fields[6], CultureInfo.InvariantCulture),
                InputBytes = int.Parse(fields[7], CultureInfo.InvariantCulture),
                OutputBytes = int.Parse(fields[8], CultureInfo.InvariantCulture),
                ElapsedMilliseconds = double.Parse(fields[9], CultureInfo.InvariantCulture),
                ThroughputMegabytesPerSecond = double.Parse(fields[10], CultureInfo.InvariantCulture),
                Succeeded = bool.Parse(fields[11]),
                RelativeSpeedupVsNativeCpu = string.IsNullOrWhiteSpace(fields[12]) ? null : double.Parse(fields[12], CultureInfo.InvariantCulture),
                RelativeSpeedupVsManagedAes = string.IsNullOrWhiteSpace(fields[13]) ? null : double.Parse(fields[13], CultureInfo.InvariantCulture),
                Note = fields[14]
            });
        }

        var request = new BenchmarkRequest
        {
            Algorithm = Enum.Parse<CryptoAlgorithm>(metadata["Algorithm"], true),
            Padding = metadata["Padding"].Equals("N/A", StringComparison.OrdinalIgnoreCase) ? CryptoPaddingMode.None : Enum.Parse<CryptoPaddingMode>(metadata["Padding"], true),
            KeySizeBits = int.Parse(metadata["KeySizeBits"], CultureInfo.InvariantCulture),
            DataSizeMegabytes = int.Parse(metadata["DataSizeMegabytes"], CultureInfo.InvariantCulture),
            IterationCount = int.Parse(metadata["IterationCount"], CultureInfo.InvariantCulture),
            WarmupBeforeRun = bool.Parse(metadata["WarmupBeforeRun"]),
            Password = metadata.GetValueOrDefault("Password", string.Empty)
        };

        var environmentInfo = new BenchmarkEnvironmentInfo
        {
            FrameworkDescription = metadata.GetValueOrDefault("FrameworkDescription", string.Empty),
            OperatingSystemDescription = metadata.GetValueOrDefault("OperatingSystemDescription", string.Empty),
            WindowsVersion = metadata.GetValueOrDefault("WindowsVersion", string.Empty),
            WindowsBuild = metadata.GetValueOrDefault("WindowsBuild", string.Empty),
            ProcessArchitecture = metadata.GetValueOrDefault("ProcessArchitecture", string.Empty),
            BuildArchitecture = metadata.GetValueOrDefault("BuildArchitecture", string.Empty),
            LogicalProcessorCount = metadata.GetValueOrDefault("LogicalProcessorCount", string.Empty),
            ProcessorName = metadata.GetValueOrDefault("ProcessorName", string.Empty),
            ProcessorCoreCount = metadata.GetValueOrDefault("ProcessorCoreCount", string.Empty),
            ProcessorLogicalCoreCount = metadata.GetValueOrDefault("ProcessorLogicalCoreCount", string.Empty),
            ProcessorMaxClockMHz = metadata.GetValueOrDefault("ProcessorMaxClockMHz", string.Empty),
            GpuName = metadata.GetValueOrDefault("GpuName", string.Empty),
            MotherboardName = metadata.GetValueOrDefault("MotherboardName", string.Empty),
            PowerSource = metadata.GetValueOrDefault("PowerSource", string.Empty),
            WindowsPowerPlan = metadata.GetValueOrDefault("WindowsPowerPlan", string.Empty),
            RamTotal = metadata.GetValueOrDefault("RamTotal", string.Empty),
            RamModules = metadata.GetValueOrDefault("RamModules", string.Empty),
            OpenClPlatformName = metadata.GetValueOrDefault("OpenClPlatformName", string.Empty),
            OpenClPlatformVersion = metadata.GetValueOrDefault("OpenClPlatformVersion", string.Empty),
            OpenClDeviceName = metadata.GetValueOrDefault("OpenClDeviceName", string.Empty),
            OpenClDeviceVersion = metadata.GetValueOrDefault("OpenClDeviceVersion", string.Empty),
            OpenClCVersion = metadata.GetValueOrDefault("OpenClCVersion", string.Empty),
            OpenClInfoStatus = metadata.GetValueOrDefault("OpenClInfoStatus", string.Empty)
        };

        return new BenchmarkSession
        {
            SessionId = Guid.Parse(metadata["SessionId"]),
            CreatedUtc = DateTimeOffset.Parse(metadata["CreatedUtc"], CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
            Request = request,
            SaltBase64 = metadata.GetValueOrDefault("SaltBase64", string.Empty),
            Iv16Base64 = metadata.GetValueOrDefault("Iv16Base64", string.Empty),
            Iv12Base64 = metadata.GetValueOrDefault("Iv12Base64", string.Empty),
            AadBase64 = metadata.GetValueOrDefault("AadBase64", string.Empty),
            Rows = rows,
            Summaries = BuildSummaries(rows),
            EnvironmentInfo = environmentInfo,
            EnvironmentDescription = metadata.GetValueOrDefault("EnvironmentDescription", string.Empty),
            Notes = metadata.GetValueOrDefault("Notes", string.Empty)
        };
    }

    private static void AppendMetadata(StringBuilder builder, string key, string value)
    {
        builder.Append('#');
        builder.Append(key);
        builder.Append(',');
        builder.AppendLine(Escape(value ?? string.Empty));
    }

    private static string Escape(string value)
    {
        if (value.Contains('"') || value.Contains(',') || value.Contains('\n') || value.Contains('\r'))
        {
            return $"\"{value.Replace("\"", "\"\"")}\"";
        }

        return value;
    }

    private static string Unescape(string value)
    {
        if (value.Length >= 2 && value.StartsWith('"') && value.EndsWith('"'))
        {
            return value[1..^1].Replace("\"\"", "\"");
        }

        return value;
    }

    private static List<string> SplitCsvLine(string line)
    {
        var fields = new List<string>();
        var builder = new StringBuilder();
        var inQuotes = false;

        for (var index = 0; index < line.Length; index++)
        {
            var character = line[index];
            if (character == '"')
            {
                if (inQuotes && index + 1 < line.Length && line[index + 1] == '"')
                {
                    builder.Append('"');
                    index++;
                }
                else
                {
                    inQuotes = !inQuotes;
                }
            }
            else if (character == ',' && !inQuotes)
            {
                fields.Add(builder.ToString());
                builder.Clear();
            }
            else
            {
                builder.Append(character);
            }
        }

        fields.Add(builder.ToString());
        return fields;
    }

    private static IReadOnlyList<BenchmarkSummary> BuildSummaries(IReadOnlyList<BenchmarkResultRow> rows)
    {
        return rows
            .GroupBy(row => new { row.Engine, row.Direction })
            .Select(group =>
            {
                var successfulRows = group.Where(row => row.Succeeded).OrderBy(row => row.ElapsedMilliseconds).ToList();
                if (successfulRows.Count == 0)
                {
                    return new BenchmarkSummary
                    {
                        Engine = group.Key.Engine,
                        Direction = group.Key.Direction,
                        Samples = 0,
                        AverageMilliseconds = 0,
                        MedianMilliseconds = 0,
                        BestMilliseconds = 0,
                        AverageThroughputMegabytesPerSecond = 0,
                        BestThroughputMegabytesPerSecond = 0,
                        Succeeded = false,
                        Note = string.Join(" | ", group.Where(row => !string.IsNullOrWhiteSpace(row.Note)).Select(row => row.Note).Distinct())
                    };
                }

                var median = successfulRows.Count % 2 == 1
                    ? successfulRows[successfulRows.Count / 2].ElapsedMilliseconds
                    : (successfulRows[(successfulRows.Count / 2) - 1].ElapsedMilliseconds + successfulRows[successfulRows.Count / 2].ElapsedMilliseconds) / 2d;

                return new BenchmarkSummary
                {
                    Engine = group.Key.Engine,
                    Direction = group.Key.Direction,
                    Samples = successfulRows.Count,
                    AverageMilliseconds = successfulRows.Average(row => row.ElapsedMilliseconds),
                    MedianMilliseconds = median,
                    BestMilliseconds = successfulRows.Min(row => row.ElapsedMilliseconds),
                    AverageThroughputMegabytesPerSecond = successfulRows.Average(row => row.ThroughputMegabytesPerSecond),
                    BestThroughputMegabytesPerSecond = successfulRows.Max(row => row.ThroughputMegabytesPerSecond),
                    Succeeded = true,
                    RelativeSpeedupVsNativeCpu = group.Key.Engine == CryptoEngine.OpenCl ? ComputeRelativeSpeedup(group.Key.Direction, group.Key.Engine, rows, CryptoEngine.NativeCpu) : null,
                    RelativeSpeedupVsManagedAes = null
                };
            })
            .OrderBy(summary => summary.Direction)
            .ThenBy(summary => summary.Engine)
            .ToList();
    }

    private static double? ComputeRelativeSpeedup(BenchmarkDirection direction, CryptoEngine engine, IReadOnlyList<BenchmarkResultRow> rows, CryptoEngine baselineEngine)
    {
        var candidateRows = rows.Where(row => row.Direction == direction && row.Engine == engine && row.Succeeded).ToList();
        var baselineRows = rows.Where(row => row.Direction == direction && row.Engine == baselineEngine && row.Succeeded).ToList();
        if (candidateRows.Count == 0 || baselineRows.Count == 0)
        {
            return null;
        }

        var candidateAverage = candidateRows.Average(row => row.ElapsedMilliseconds);
        var baselineAverage = baselineRows.Average(row => row.ElapsedMilliseconds);
        if (candidateAverage <= 0 || baselineAverage <= 0)
        {
            return null;
        }

        return baselineAverage / candidateAverage;
    }
}
