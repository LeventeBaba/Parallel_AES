using System.Security.Cryptography;

namespace AES.WinForms.Services;

public sealed class PasswordDerivationService
{
    public const int DefaultIterationCount = 200_000;

    public byte[] CreateRandomBytes(int length)
    {
        var bytes = new byte[length];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }

    public byte[] DeriveKey(string password, byte[] salt, int keySizeBits, int iterationCount = DefaultIterationCount)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            throw new ArgumentException("A password is required.", nameof(password));
        }

        if (keySizeBits is not (128 or 192 or 256))
        {
            throw new ArgumentOutOfRangeException(nameof(keySizeBits), "The key size must be 128, 192, or 256 bits.");
        }

        return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterationCount, HashAlgorithmName.SHA256, keySizeBits / 8);
    }
}
