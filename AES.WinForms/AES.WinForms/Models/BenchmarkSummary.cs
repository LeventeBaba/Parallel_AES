namespace AES.WinForms.Models;

public sealed class BenchmarkSummary
{
    public required CryptoEngine Engine { get; init; }
    public required BenchmarkDirection Direction { get; init; }
    public required int Samples { get; init; }
    public required double AverageMilliseconds { get; init; }
    public required double MedianMilliseconds { get; init; }
    public required double BestMilliseconds { get; init; }
    public required double AverageThroughputMegabytesPerSecond { get; init; }
    public required double BestThroughputMegabytesPerSecond { get; init; }
    public required bool Succeeded { get; init; }
    public string Note { get; init; } = string.Empty;
    public double? RelativeSpeedupVsNativeCpu { get; init; }
    public double? RelativeSpeedupVsManagedAes { get; init; }
}
