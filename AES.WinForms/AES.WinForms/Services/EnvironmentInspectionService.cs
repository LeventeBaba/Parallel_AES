using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using AES.WinForms.Models;
using AES.WinForms.Native;
using Microsoft.Win32;
using System.Windows.Forms;

namespace AES.WinForms.Services;

public sealed class EnvironmentInspectionService
{
    private readonly NativeCryptoFacade _nativeCryptoFacade;

    public EnvironmentInspectionService(NativeCryptoFacade nativeCryptoFacade)
    {
        _nativeCryptoFacade = nativeCryptoFacade;
    }

    public BenchmarkEnvironmentInfo CollectBenchmarkEnvironmentInfo()
    {
        var info = new BenchmarkEnvironmentInfo
        {
            FrameworkDescription = RuntimeInformation.FrameworkDescription,
            OperatingSystemDescription = RuntimeInformation.OSDescription,
            ProcessArchitecture = RuntimeInformation.ProcessArchitecture.ToString(),
            BuildArchitecture = Environment.Is64BitProcess ? "x64" : "x86",
            LogicalProcessorCount = Environment.ProcessorCount.ToString(CultureInfo.InvariantCulture),
            PowerSource = GetPowerSource(),
            WindowsPowerPlan = GetWindowsPowerPlan()
        };

        PopulateWindowsVersion(info);
        PopulateHardwareInfo(info);
        PopulateOpenClInfo(info);

        return info;
    }

    public string BuildEnvironmentDescription(BenchmarkEnvironmentInfo info)
    {
        var parts = new List<string>();

        AddPart(parts, info.FrameworkDescription);
        AddPart(parts, info.WindowsVersion);
        AddPart(parts, info.BuildArchitecture);

        if (!string.IsNullOrWhiteSpace(info.ProcessorName))
        {
            var cpu = info.ProcessorName;
            var cpuDetails = new List<string>();
            if (!string.IsNullOrWhiteSpace(info.ProcessorCoreCount))
            {
                cpuDetails.Add($"Cores: {info.ProcessorCoreCount}");
            }

            if (!string.IsNullOrWhiteSpace(info.ProcessorLogicalCoreCount))
            {
                cpuDetails.Add($"Logical: {info.ProcessorLogicalCoreCount}");
            }

            if (!string.IsNullOrWhiteSpace(info.ProcessorMaxClockMHz))
            {
                cpuDetails.Add($"Max MHz: {info.ProcessorMaxClockMHz}");
            }

            if (cpuDetails.Count > 0)
            {
                cpu = $"{cpu} ({string.Join(", ", cpuDetails)})";
            }

            parts.Add(cpu);
        }

        if (!string.IsNullOrWhiteSpace(info.GpuName))
        {
            parts.Add($"GPU: {info.GpuName}");
        }

        if (!string.IsNullOrWhiteSpace(info.RamTotal))
        {
            parts.Add($"RAM: {info.RamTotal}");
        }

        if (!string.IsNullOrWhiteSpace(info.PowerSource))
        {
            parts.Add($"Power: {info.PowerSource}");
        }

        if (!string.IsNullOrWhiteSpace(info.OpenClDeviceVersion))
        {
            parts.Add($"OpenCL: {info.OpenClDeviceVersion}");
        }

        return string.Join(" | ", parts.Where(static part => !string.IsNullOrWhiteSpace(part)));
    }

    public string BuildDiagnosticsReport()
    {
        var info = CollectBenchmarkEnvironmentInfo();
        var lines = new List<string>
        {
            $"Framework: {info.FrameworkDescription}",
            $"OS: {info.OperatingSystemDescription}",
            $"Windows version: {info.WindowsVersion}",
            $"Windows build: {info.WindowsBuild}",
            $"Process architecture: {info.ProcessArchitecture}",
            $"Build architecture: {info.BuildArchitecture}",
            $"Logical processors: {info.LogicalProcessorCount}",
            $"CPU: {info.ProcessorName}",
            $"CPU cores: {info.ProcessorCoreCount}",
            $"CPU logical cores: {info.ProcessorLogicalCoreCount}",
            $"CPU max clock MHz: {info.ProcessorMaxClockMHz}",
            $"GPU: {info.GpuName}",
            $"Motherboard: {info.MotherboardName}",
            $"Power source: {info.PowerSource}",
            $"Windows power plan: {info.WindowsPowerPlan}",
            $"RAM total: {info.RamTotal}",
            $"RAM modules: {info.RamModules}",
            $"OpenCL platform: {info.OpenClPlatformName}",
            $"OpenCL platform version: {info.OpenClPlatformVersion}",
            $"OpenCL device: {info.OpenClDeviceName}",
            $"OpenCL device version: {info.OpenClDeviceVersion}",
            $"OpenCL C version: {info.OpenClCVersion}",
            $"OpenCL info status: {info.OpenClInfoStatus}",
            $"Application base directory: {AppContext.BaseDirectory}",
            $"crypto_aes.dll present: {File.Exists(Path.Combine(AppContext.BaseDirectory, "crypto_aes.dll"))}",
            $"crypto_aes_opencl.dll present: {File.Exists(Path.Combine(AppContext.BaseDirectory, "crypto_aes_opencl.dll"))}",
            $"kernel_loader.dll present: {File.Exists(Path.Combine(AppContext.BaseDirectory, "kernel_loader.dll"))}",
            $"kernels folder present: {Directory.Exists(Path.Combine(AppContext.BaseDirectory, "kernels"))}"
        };

        if (_nativeCryptoFacade.TryWarmupOpenCl(out var warmupMessage))
        {
            lines.Add(warmupMessage);
        }
        else
        {
            lines.Add(warmupMessage);
            lines.Add($"OpenCL details: {_nativeCryptoFacade.GetOpenClLastErrorMessage()}");
        }

        return string.Join(Environment.NewLine, lines);
    }

    private static void PopulateWindowsVersion(BenchmarkEnvironmentInfo info)
    {
        if (!OperatingSystem.IsWindows())
        {
            info.WindowsVersion = RuntimeInformation.OSDescription;
            info.WindowsBuild = RuntimeInformation.OSDescription;
            return;
        }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            var productName = key?.GetValue("ProductName")?.ToString() ?? "Windows";
            var displayVersion = key?.GetValue("DisplayVersion")?.ToString();
            if (string.IsNullOrWhiteSpace(displayVersion))
            {
                displayVersion = key?.GetValue("ReleaseId")?.ToString();
            }

            var currentBuild = key?.GetValue("CurrentBuildNumber")?.ToString() ?? string.Empty;
            var ubr = key?.GetValue("UBR")?.ToString() ?? string.Empty;
            info.WindowsVersion = string.IsNullOrWhiteSpace(displayVersion) ? productName : $"{productName} {displayVersion}";
            info.WindowsBuild = string.IsNullOrWhiteSpace(currentBuild)
                ? RuntimeInformation.OSDescription
                : string.IsNullOrWhiteSpace(ubr)
                    ? $"Build {currentBuild}"
                    : $"Build {currentBuild}.{ubr}";
        }
        catch
        {
            info.WindowsVersion = RuntimeInformation.OSDescription;
            info.WindowsBuild = RuntimeInformation.OSDescription;
        }
    }

    private static void PopulateHardwareInfo(BenchmarkEnvironmentInfo info)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var output = RunPowerShellCimQuery();
        if (string.IsNullOrWhiteSpace(output))
        {
            return;
        }

        try
        {
            using var document = JsonDocument.Parse(output);
            var root = document.RootElement;
            PopulateProcessor(root, info);
            PopulateGpus(root, info);
            PopulateBaseBoard(root, info);
            PopulateMemory(root, info);
        }
        catch
        {
        }
    }

    private void PopulateOpenClInfo(BenchmarkEnvironmentInfo info)
    {
        if (_nativeCryptoFacade.TryGetOpenClEnvironmentInfo(out var platformName, out var platformVersion, out var deviceName, out var deviceVersion, out var cVersion, out var statusMessage))
        {
            info.OpenClPlatformName = platformName;
            info.OpenClPlatformVersion = platformVersion;
            info.OpenClDeviceName = deviceName;
            info.OpenClDeviceVersion = deviceVersion;
            info.OpenClCVersion = cVersion;
            info.OpenClInfoStatus = statusMessage;
            return;
        }

        info.OpenClInfoStatus = statusMessage;
    }

    private static void PopulateProcessor(JsonElement root, BenchmarkEnvironmentInfo info)
    {
        if (!root.TryGetProperty("Processor", out var processor) || processor.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        info.ProcessorName = GetJsonString(processor, "Name");
        info.ProcessorCoreCount = GetJsonString(processor, "NumberOfCores");
        info.ProcessorLogicalCoreCount = GetJsonString(processor, "NumberOfLogicalProcessors");
        info.ProcessorMaxClockMHz = GetJsonString(processor, "MaxClockSpeed");
    }

    private static void PopulateGpus(JsonElement root, BenchmarkEnvironmentInfo info)
    {
        if (!root.TryGetProperty("Gpus", out var gpus))
        {
            return;
        }

        var names = EnumerateObjects(gpus)
            .Select(gpu => GetJsonString(gpu, "Name"))
            .Where(static name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        info.GpuName = string.Join(" | ", names);
    }

    private static void PopulateBaseBoard(JsonElement root, BenchmarkEnvironmentInfo info)
    {
        if (!root.TryGetProperty("BaseBoard", out var board) || board.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        var parts = new List<string>();
        AddPart(parts, GetJsonString(board, "Manufacturer"));
        AddPart(parts, GetJsonString(board, "Product"));
        info.MotherboardName = string.Join(" ", parts);
    }

    private static void PopulateMemory(JsonElement root, BenchmarkEnvironmentInfo info)
    {
        if (!root.TryGetProperty("Memory", out var memory))
        {
            return;
        }

        var modules = EnumerateObjects(memory).ToList();
        if (modules.Count == 0)
        {
            return;
        }

        long totalBytes = 0;
        var moduleDescriptions = new List<string>();
        var configuredSpeeds = new List<string>();

        foreach (var module in modules)
        {
            var capacityBytes = GetJsonInt64(module, "Capacity");
            if (capacityBytes > 0)
            {
                totalBytes += capacityBytes;
            }

            var configuredClockSpeed = GetJsonString(module, "ConfiguredClockSpeed");
            var speed = string.IsNullOrWhiteSpace(configuredClockSpeed) ? GetJsonString(module, "Speed") : configuredClockSpeed;
            if (!string.IsNullOrWhiteSpace(speed))
            {
                configuredSpeeds.Add(speed);
            }

            var parts = new List<string>();
            if (capacityBytes > 0)
            {
                parts.Add(FormatBytes(capacityBytes));
            }

            if (!string.IsNullOrWhiteSpace(speed))
            {
                parts.Add($"{speed} MHz");
            }

            var manufacturer = GetJsonString(module, "Manufacturer");
            if (!string.IsNullOrWhiteSpace(manufacturer))
            {
                parts.Add(manufacturer.Trim());
            }

            var partNumber = GetJsonString(module, "PartNumber");
            if (!string.IsNullOrWhiteSpace(partNumber))
            {
                parts.Add(partNumber.Trim());
            }

            if (parts.Count > 0)
            {
                moduleDescriptions.Add(string.Join(" ", parts));
            }
        }

        var summaryParts = new List<string>();
        if (totalBytes > 0)
        {
            summaryParts.Add(FormatBytes(totalBytes));
        }

        summaryParts.Add($"{modules.Count} module(s)");

        var distinctSpeeds = configuredSpeeds
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (distinctSpeeds.Count > 0)
        {
            summaryParts.Add($"{string.Join(" / ", distinctSpeeds)} MHz");
        }

        info.RamTotal = string.Join(", ", summaryParts);
        info.RamModules = string.Join(" | ", moduleDescriptions);
    }

    private static IEnumerable<JsonElement> EnumerateObjects(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            yield return element;
            yield break;
        }

        if (element.ValueKind != JsonValueKind.Array)
        {
            yield break;
        }

        foreach (var item in element.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.Object)
            {
                yield return item;
            }
        }
    }

    private static string GetJsonString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value))
        {
            return string.Empty;
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString() ?? string.Empty,
            JsonValueKind.Number => value.ToString(),
            JsonValueKind.True => bool.TrueString,
            JsonValueKind.False => bool.FalseString,
            _ => string.Empty
        };
    }

    private static long GetJsonInt64(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value))
        {
            return 0;
        }

        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var result))
        {
            return result;
        }

        if (value.ValueKind == JsonValueKind.String && long.TryParse(value.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out result))
        {
            return result;
        }

        return 0;
    }

    private static string FormatBytes(long bytes)
    {
        const double gib = 1024d * 1024d * 1024d;
        const double mib = 1024d * 1024d;
        return bytes >= gib
            ? $"{bytes / gib:F2} GiB"
            : $"{bytes / mib:F2} MiB";
    }

    private static string GetPowerSource()
    {
        if (!OperatingSystem.IsWindows())
        {
            return "Unknown";
        }

        return SystemInformation.PowerStatus.PowerLineStatus switch
        {
            PowerLineStatus.Online => "AC power",
            PowerLineStatus.Offline => "Battery",
            PowerLineStatus.Unknown => SystemInformation.PowerStatus.BatteryChargeStatus.HasFlag(BatteryChargeStatus.NoSystemBattery) ? "No battery" : "Unknown",
            _ => "Unknown"
        };
    }

    private static string GetWindowsPowerPlan()
    {
        if (!OperatingSystem.IsWindows())
        {
            return "Unknown";
        }

        try
        {
            using var process = new Process();
            process.StartInfo.FileName = "powercfg";
            process.StartInfo.Arguments = "/getactivescheme";
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.CreateNoWindow = true;
            process.Start();
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(3000);

            if (string.IsNullOrWhiteSpace(output))
            {
                return "Unknown";
            }

            var match = Regex.Match(output, @"([0-9a-fA-F\-]{36}).*\(([^\)]+)\)");
            if (match.Success)
            {
                return $"{match.Groups[2].Value.Trim()} [{match.Groups[1].Value.Trim()}]";
            }

            return output.Trim();
        }
        catch
        {
            return "Unknown";
        }
    }

    private static string? RunPowerShellCimQuery()
    {
        try
        {
            using var process = new Process();
            process.StartInfo.FileName = "powershell.exe";
            process.StartInfo.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"$processor = Get-CimInstance Win32_Processor | Select-Object -First 1 Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed; $gpus = @(Get-CimInstance Win32_VideoController | Select-Object Name); $board = Get-CimInstance Win32_BaseBoard | Select-Object -First 1 Manufacturer, Product; $memory = @(Get-CimInstance Win32_PhysicalMemory | Select-Object Capacity, Speed, ConfiguredClockSpeed, Manufacturer, PartNumber, SMBIOSMemoryType); [pscustomobject]@{ Processor = $processor; Gpus = $gpus; BaseBoard = $board; Memory = $memory } | ConvertTo-Json -Compress -Depth 5\"";
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.CreateNoWindow = true;
            process.Start();
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(8000);
            return process.ExitCode == 0 ? output.Trim() : null;
        }
        catch
        {
            return null;
        }
    }

    private static void AddPart(ICollection<string> parts, string value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            parts.Add(value.Trim());
        }
    }
}
