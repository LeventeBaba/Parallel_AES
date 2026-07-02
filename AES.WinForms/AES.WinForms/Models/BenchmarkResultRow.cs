namespace AES.WinForms.Models;

public sealed class BenchmarkResultRow
{
    public required Guid SessionId { get; init; }
    public required DateTimeOffset TimestampUtc { get; init; }
    public required int Iteration { get; init; }
    public required CryptoAlgorithm Algorithm { get; init; }
    public required CryptoPaddingMode Padding { get; init; }
    public required int KeySizeBits { get; init; }
    public required int InputBytes { get; init; }
    public required int OutputBytes { get; init; }
    public required CryptoEngine Engine { get; init; }
    public required BenchmarkDirection Direction { get; init; }
    public required double ElapsedMilliseconds { get; init; }
    public required double ThroughputMegabytesPerSecond { get; init; }
    public required bool Succeeded { get; init; }
    public string Note { get; init; } = string.Empty;
    public double? RelativeSpeedupVsNativeCpu { get; set; }
    public double? RelativeSpeedupVsManagedAes { get; set; }
}
