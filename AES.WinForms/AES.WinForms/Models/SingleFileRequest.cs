namespace AES.WinForms.Models;

public sealed class SingleFileRequest
{
    public bool Encrypt { get; init; }
    public CryptoEngine Engine { get; init; }
    public CryptoAlgorithm Algorithm { get; init; }
    public CryptoPaddingMode Padding { get; init; }
    public int KeySizeBits { get; init; }
    public string Password { get; init; } = string.Empty;
    public string InputPath { get; init; } = string.Empty;
    public string OutputPath { get; init; } = string.Empty;
}
