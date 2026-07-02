namespace AES.WinForms.Models;

public sealed class BenchmarkRequest
{
    public required CryptoAlgorithm Algorithm { get; init; }
    public required CryptoPaddingMode Padding { get; init; }
    public required int KeySizeBits { get; init; }
    public required int DataSizeMegabytes { get; init; }
    public required int IterationCount { get; init; }
    public required string Password { get; init; }
    public bool WarmupBeforeRun { get; init; }
}
