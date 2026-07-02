namespace AES.WinForms.Models;

public sealed class BenchmarkEnvironmentInfo
{
    public string FrameworkDescription { get; set; } = string.Empty;
    public string OperatingSystemDescription { get; set; } = string.Empty;
    public string WindowsVersion { get; set; } = string.Empty;
    public string WindowsBuild { get; set; } = string.Empty;
    public string ProcessArchitecture { get; set; } = string.Empty;
    public string BuildArchitecture { get; set; } = string.Empty;
    public string LogicalProcessorCount { get; set; } = string.Empty;
    public string ProcessorName { get; set; } = string.Empty;
    public string ProcessorCoreCount { get; set; } = string.Empty;
    public string ProcessorLogicalCoreCount { get; set; } = string.Empty;
    public string ProcessorMaxClockMHz { get; set; } = string.Empty;
    public string GpuName { get; set; } = string.Empty;
    public string MotherboardName { get; set; } = string.Empty;
    public string PowerSource { get; set; } = string.Empty;
    public string WindowsPowerPlan { get; set; } = string.Empty;
    public string RamTotal { get; set; } = string.Empty;
    public string RamModules { get; set; } = string.Empty;
    public string OpenClPlatformName { get; set; } = string.Empty;
    public string OpenClPlatformVersion { get; set; } = string.Empty;
    public string OpenClDeviceName { get; set; } = string.Empty;
    public string OpenClDeviceVersion { get; set; } = string.Empty;
    public string OpenClCVersion { get; set; } = string.Empty;
    public string OpenClInfoStatus { get; set; } = string.Empty;
}
