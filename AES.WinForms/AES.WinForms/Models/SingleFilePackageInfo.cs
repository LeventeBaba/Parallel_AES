namespace AES.WinForms.Models;

public sealed class SingleFilePackageInfo
{
    public CryptoAlgorithm Algorithm { get; init; }
    public CryptoPaddingMode Padding { get; init; }
    public int KeySizeBits { get; init; }
    public int IterationCount { get; init; }
    public byte[] Salt { get; init; } = Array.Empty<byte>();
    public byte[] Iv { get; init; } = Array.Empty<byte>();
    public byte[] Tag { get; init; } = Array.Empty<byte>();
    public long PayloadOffset { get; init; }
    public long PayloadLength { get; init; }
}
