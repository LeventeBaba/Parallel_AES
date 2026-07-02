using System.Security.Cryptography;
using AES.WinForms.Models;

namespace AES.WinForms.Services;

public sealed class ManagedCryptoService
{
    public byte[] Encrypt(CryptoAlgorithm algorithm, CryptoPaddingMode padding, byte[] key, byte[] iv16, byte[] iv12, byte[] aad, byte[] plaintext, out byte[] tag)
    {
        return algorithm switch
        {
            CryptoAlgorithm.Cbc => EncryptCbc(padding, key, iv16, plaintext, out tag),
            CryptoAlgorithm.Gcm => EncryptGcm(key, iv12, aad, plaintext, out tag),
            _ => throw new NotSupportedException($"Managed AES does not support {algorithm} in this application.")
        };
    }

    public byte[] Decrypt(CryptoAlgorithm algorithm, CryptoPaddingMode padding, byte[] key, byte[] iv16, byte[] iv12, byte[] aad, byte[] ciphertext, byte[] tag)
    {
        return algorithm switch
        {
            CryptoAlgorithm.Cbc => DecryptCbc(padding, key, iv16, ciphertext),
            CryptoAlgorithm.Gcm => DecryptGcm(key, iv12, aad, ciphertext, tag),
            _ => throw new NotSupportedException($"Managed AES does not support {algorithm} in this application.")
        };
    }

    public bool IsSupported(CryptoAlgorithm algorithm, CryptoPaddingMode padding)
    {
        return algorithm switch
        {
            CryptoAlgorithm.Cbc => padding is CryptoPaddingMode.Pkcs7 or CryptoPaddingMode.AnsiX923 or CryptoPaddingMode.Zero or CryptoPaddingMode.None,
            CryptoAlgorithm.Gcm => AesGcm.IsSupported,
            _ => false
        };
    }

    private static byte[] EncryptCbc(CryptoPaddingMode padding, byte[] key, byte[] iv16, byte[] plaintext, out byte[] tag)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv16;
        aes.Mode = CipherMode.CBC;
        aes.Padding = ToPaddingMode(padding);

        using var transform = aes.CreateEncryptor();
        tag = Array.Empty<byte>();
        return transform.TransformFinalBlock(plaintext, 0, plaintext.Length);
    }

    private static byte[] DecryptCbc(CryptoPaddingMode padding, byte[] key, byte[] iv16, byte[] ciphertext)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv16;
        aes.Mode = CipherMode.CBC;
        aes.Padding = ToPaddingMode(padding);

        using var transform = aes.CreateDecryptor();
        return transform.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
    }

    private static byte[] EncryptGcm(byte[] key, byte[] iv12, byte[] aad, byte[] plaintext, out byte[] tag)
    {
        var ciphertext = new byte[plaintext.Length];
        tag = new byte[16];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(iv12, plaintext, ciphertext, tag, aad);
        return ciphertext;
    }

    private static byte[] DecryptGcm(byte[] key, byte[] iv12, byte[] aad, byte[] ciphertext, byte[] tag)
    {
        var plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(iv12, ciphertext, tag, plaintext, aad);
        return plaintext;
    }

    private static PaddingMode ToPaddingMode(CryptoPaddingMode padding)
    {
        return padding switch
        {
            CryptoPaddingMode.Pkcs7 => PaddingMode.PKCS7,
            CryptoPaddingMode.AnsiX923 => PaddingMode.ANSIX923,
            CryptoPaddingMode.Zero => PaddingMode.Zeros,
            CryptoPaddingMode.None => PaddingMode.None,
            _ => throw new NotSupportedException($"Managed AES does not support {padding} padding.")
        };
    }
}
