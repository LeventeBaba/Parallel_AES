using System.Runtime.InteropServices;
using AES.WinForms.Models;

namespace AES.WinForms.Native;

public sealed class NativeCryptoFacade
{
    public byte[] Encrypt(CryptoEngine engine, CryptoAlgorithm algorithm, CryptoPaddingMode padding, byte[] key, byte[] iv16, byte[] iv12, byte[] aad, byte[] plaintext, out byte[] tag)
    {
        return Transform(true, engine, algorithm, padding, key, iv16, iv12, aad, plaintext, Array.Empty<byte>(), out tag);
    }

    public byte[] Decrypt(CryptoEngine engine, CryptoAlgorithm algorithm, CryptoPaddingMode padding, byte[] key, byte[] iv16, byte[] iv12, byte[] aad, byte[] ciphertext, byte[] tag)
    {
        return Transform(false, engine, algorithm, padding, key, iv16, iv12, aad, ciphertext, tag, out _);
    }

    public void EncryptAndDiscard(CryptoEngine engine, CryptoAlgorithm algorithm, CryptoPaddingMode padding, byte[] key, byte[] iv16, byte[] iv12, byte[] aad, byte[] plaintext, out byte[] tag)
    {
        ExecuteDiscard(true, engine, algorithm, padding, key, iv16, iv12, aad, plaintext, Array.Empty<byte>(), out tag);
    }

    public void DecryptAndDiscard(CryptoEngine engine, CryptoAlgorithm algorithm, CryptoPaddingMode padding, byte[] key, byte[] iv16, byte[] iv12, byte[] aad, byte[] ciphertext, byte[] tag)
    {
        ExecuteDiscard(false, engine, algorithm, padding, key, iv16, iv12, aad, ciphertext, tag, out _);
    }


    public byte[] EncryptFile(CryptoEngine engine, CryptoAlgorithm algorithm, CryptoPaddingMode padding, byte[] key, byte[] iv, byte[] aad, string inputPath, string outputPath)
    {
        return ProcessFile(true, engine, algorithm, padding, key, iv, aad, inputPath, outputPath, Array.Empty<byte>());
    }

    public void DecryptFile(CryptoEngine engine, CryptoAlgorithm algorithm, CryptoPaddingMode padding, byte[] key, byte[] iv, byte[] aad, string inputPath, string outputPath, byte[] tag)
    {
        ProcessFile(false, engine, algorithm, padding, key, iv, aad, inputPath, outputPath, tag);
    }

    public bool TryWarmupOpenCl(out string message)
    {
        try
        {
            var status = NativeOpenClMethods.Warmup();
            if (status == NativeStatus.Ok)
            {
                message = "OpenCL warmup completed successfully.";
                return true;
            }

            message = $"OpenCL warmup failed: {GetOpenClErrorMessage(status)}";
            return false;
        }
        catch (BadImageFormatException ex)
        {
            message = $"OpenCL warmup failed: {BuildOpenClLoadFailureHint(ex.Message)}";
            return false;
        }
        catch (DllNotFoundException ex)
        {
            message = $"OpenCL warmup failed: {BuildOpenClLoadFailureHint(ex.Message)}";
            return false;
        }
        catch (Exception ex)
        {
            message = $"OpenCL warmup failed: {ex.Message}";
            return false;
        }
    }

    private static string BuildOpenClLoadFailureHint(string rawMessage)
    {
        var architecture = Environment.Is64BitProcess ? "x64" : "x86";
        var hint = $"{rawMessage} (Process architecture: {architecture}).";

        if (!Environment.Is64BitProcess)
        {
            hint += " This typically means a 32-bit dependency of crypto_aes_opencl.dll could not be loaded. Ensure that a 32-bit OpenCL runtime is installed (GPU driver / ICD loader) and that all native DLL dependencies are present next to the executable. If you only have a 64-bit OpenCL runtime, use the x64 build.";
        }
        else
        {
            hint += " Ensure that the OpenCL runtime is installed and all native DLL dependencies are present next to the executable.";
        }

        return hint;
    }

    public string GetOpenClLastErrorMessage()
    {
        try
        {
            return GetOpenClErrorMessage(null);
        }
        catch
        {
            return "No OpenCL diagnostic message is currently available.";
        }
    }

    public bool TryGetOpenClEnvironmentInfo(out string platformName, out string platformVersion, out string deviceName, out string deviceVersion, out string openClCVersion, out string statusMessage)
    {
        platformName = string.Empty;
        platformVersion = string.Empty;
        deviceName = string.Empty;
        deviceVersion = string.Empty;
        openClCVersion = string.Empty;

        try
        {
            platformName = NativeOpenClMethods.GetPlatformName();
            platformVersion = NativeOpenClMethods.GetPlatformVersion();
            deviceName = NativeOpenClMethods.GetDeviceName();
            deviceVersion = NativeOpenClMethods.GetDeviceVersion();
            openClCVersion = NativeOpenClMethods.GetDeviceOpenClCVersion();

            if (string.IsNullOrWhiteSpace(platformName) && string.IsNullOrWhiteSpace(deviceName) && string.IsNullOrWhiteSpace(deviceVersion))
            {
                statusMessage = GetOpenClLastErrorMessage();
                return false;
            }

            statusMessage = "OpenCL platform and device information resolved successfully.";
            return true;
        }
        catch (Exception ex)
        {
            statusMessage = $"Failed to query OpenCL platform and device information: {ex.Message}";
            return false;
        }
    }

    public bool IsSupported(CryptoEngine engine, CryptoAlgorithm algorithm)
    {
        return engine switch
        {
            CryptoEngine.NativeCpu => true,
            CryptoEngine.OpenCl => algorithm is CryptoAlgorithm.Ctr or CryptoAlgorithm.Gcm,
            CryptoEngine.ManagedAes => algorithm is CryptoAlgorithm.Cbc or CryptoAlgorithm.Gcm,
            _ => false
        };
    }

    private byte[] ProcessFile(bool encrypt, CryptoEngine engine, CryptoAlgorithm algorithm, CryptoPaddingMode padding, byte[] key, byte[] iv, byte[] aad, string inputPath, string outputPath, byte[] tag)
    {
        if (engine == CryptoEngine.ManagedAes)
        {
            throw new NotSupportedException("Managed AES is handled by a dedicated managed service.");
        }

        byte[] producedTag;
        var status = engine switch
        {
            CryptoEngine.NativeCpu => ProcessCpuFile(encrypt, algorithm, padding, key, iv, aad, inputPath, outputPath, tag, out producedTag),
            CryptoEngine.OpenCl => ProcessOpenClFile(encrypt, algorithm, padding, key, iv, aad, inputPath, outputPath, tag, out producedTag),
            _ => throw new NotSupportedException($"Unsupported engine: {engine}.")
        };

        EnsureSuccess(engine, status);
        return producedTag;
    }

    private static NativeStatus ProcessCpuFile(bool encrypt, CryptoAlgorithm algorithm, CryptoPaddingMode padding, byte[] key, byte[] iv, byte[] aad, string inputPath, string outputPath, byte[] tag, out byte[] producedTag)
    {
        producedTag = Array.Empty<byte>();

        return algorithm switch
        {
            CryptoAlgorithm.Cbc when encrypt => NativeCpuMethods.AesCbcEncryptFile(key, (nuint)key.Length, iv, (int)padding, inputPath, outputPath, 0),
            CryptoAlgorithm.Cbc => NativeCpuMethods.AesCbcDecryptFile(key, (nuint)key.Length, iv, (int)padding, inputPath, outputPath, 0),
            CryptoAlgorithm.Ctr when encrypt => NativeCpuMethods.AesCtrEncryptFile(key, (nuint)key.Length, iv, (int)padding, inputPath, outputPath, 0),
            CryptoAlgorithm.Ctr => NativeCpuMethods.AesCtrDecryptFile(key, (nuint)key.Length, iv, (int)padding, inputPath, outputPath, 0),
            CryptoAlgorithm.Gcm when encrypt => EncryptCpuGcmFile(key, iv, aad, inputPath, outputPath, out producedTag),
            CryptoAlgorithm.Gcm => DecryptCpuGcmFile(key, iv, aad, inputPath, outputPath, tag),
            _ => throw new NotSupportedException($"The native CPU file API is not available for {algorithm}.")
        };
    }

    private static NativeStatus ProcessOpenClFile(bool encrypt, CryptoAlgorithm algorithm, CryptoPaddingMode padding, byte[] key, byte[] iv, byte[] aad, string inputPath, string outputPath, byte[] tag, out byte[] producedTag)
    {
        producedTag = Array.Empty<byte>();

        return algorithm switch
        {
            CryptoAlgorithm.Ctr when encrypt => NativeOpenClMethods.AesCtrEncryptFile(key, (nuint)key.Length, iv, (int)padding, inputPath, outputPath, 0),
            CryptoAlgorithm.Ctr => NativeOpenClMethods.AesCtrDecryptFile(key, (nuint)key.Length, iv, (int)padding, inputPath, outputPath, 0),
            CryptoAlgorithm.Gcm when encrypt => EncryptOpenClGcmFile(key, iv, aad, inputPath, outputPath, out producedTag),
            CryptoAlgorithm.Gcm => DecryptOpenClGcmFile(key, iv, aad, inputPath, outputPath, tag),
            _ => throw new NotSupportedException($"The OpenCL file API is not available for {algorithm}.")
        };
    }

    private void EnsureSuccess(CryptoEngine engine, NativeStatus status)
    {
        if (status == NativeStatus.Ok)
        {
            return;
        }

        if (engine == CryptoEngine.OpenCl)
        {
            throw new InvalidOperationException($"The OpenCL operation failed with {GetOpenClErrorMessage(status)}");
        }

        throw new InvalidOperationException($"The {engine} operation failed with status {(int)status} ({status}).");
    }

    private byte[] Transform(bool encrypt, CryptoEngine engine, CryptoAlgorithm algorithm, CryptoPaddingMode padding, byte[] key, byte[] iv16, byte[] iv12, byte[] aad, byte[] input, byte[] providedTag, out byte[] tag)
    {
        tag = Array.Empty<byte>();

        if (engine == CryptoEngine.ManagedAes)
        {
            throw new NotSupportedException("Managed AES is handled by a dedicated managed service.");
        }

        return engine switch
        {
            CryptoEngine.NativeCpu => TransformCpu(encrypt, algorithm, padding, key, iv16, iv12, aad, input, providedTag, out tag),
            CryptoEngine.OpenCl => TransformOpenCl(encrypt, algorithm, padding, key, iv16, iv12, aad, input, providedTag, out tag),
            _ => throw new NotSupportedException($"Unsupported engine: {engine}.")
        };
    }

    private void ExecuteDiscard(bool encrypt, CryptoEngine engine, CryptoAlgorithm algorithm, CryptoPaddingMode padding, byte[] key, byte[] iv16, byte[] iv12, byte[] aad, byte[] input, byte[] providedTag, out byte[] tag)
    {
        tag = Array.Empty<byte>();

        if (engine == CryptoEngine.ManagedAes)
        {
            throw new NotSupportedException("Managed AES is handled by a dedicated managed service.");
        }

        switch (engine)
        {
            case CryptoEngine.NativeCpu:
                ExecuteCpuDiscard(encrypt, algorithm, padding, key, iv16, iv12, aad, input, providedTag, out tag);
                return;
            case CryptoEngine.OpenCl:
                ExecuteOpenClDiscard(encrypt, algorithm, padding, key, iv16, iv12, aad, input, providedTag, out tag);
                return;
            default:
                throw new NotSupportedException($"Unsupported engine: {engine}.");
        }
    }

    private static byte[] TransformCpu(bool encrypt, CryptoAlgorithm algorithm, CryptoPaddingMode padding, byte[] key, byte[] iv16, byte[] iv12, byte[] aad, byte[] input, byte[] providedTag, out byte[] tag)
    {
        nint outputPointer = 0;
        nuint outputLength = 0;
        tag = Array.Empty<byte>();

        var status = algorithm switch
        {
            CryptoAlgorithm.Cbc when encrypt => NativeCpuMethods.AesCbcEncryptAlloc(key, (nuint)key.Length, iv16, (int)padding, input, (nuint)input.Length, out outputPointer, out outputLength),
            CryptoAlgorithm.Cbc => NativeCpuMethods.AesCbcDecryptAlloc(key, (nuint)key.Length, iv16, (int)padding, input, (nuint)input.Length, out outputPointer, out outputLength),
            CryptoAlgorithm.Ctr when encrypt => NativeCpuMethods.AesCtrEncryptAlloc(key, (nuint)key.Length, iv16, (int)padding, input, (nuint)input.Length, out outputPointer, out outputLength),
            CryptoAlgorithm.Ctr => NativeCpuMethods.AesCtrDecryptAlloc(key, (nuint)key.Length, iv16, (int)padding, input, (nuint)input.Length, out outputPointer, out outputLength),
            CryptoAlgorithm.Gcm when encrypt => EncryptCpuGcm(key, iv12, aad, input, out outputPointer, out outputLength, out tag),
            CryptoAlgorithm.Gcm => DecryptCpuGcm(key, iv12, aad, input, providedTag, out outputPointer, out outputLength),
            _ => throw new NotSupportedException($"Unsupported CPU algorithm: {algorithm}.")
        };

        return CopyAndFree(outputPointer, outputLength, status, NativeCpuMethods.Free, "native CPU");
    }

    private static byte[] TransformOpenCl(bool encrypt, CryptoAlgorithm algorithm, CryptoPaddingMode padding, byte[] key, byte[] iv16, byte[] iv12, byte[] aad, byte[] input, byte[] providedTag, out byte[] tag)
    {
        nint outputPointer = 0;
        nuint outputLength = 0;
        tag = Array.Empty<byte>();

        var status = algorithm switch
        {
            CryptoAlgorithm.Ctr when encrypt => NativeOpenClMethods.AesCtrEncryptAlloc(key, (nuint)key.Length, iv16, (int)padding, input, (nuint)input.Length, out outputPointer, out outputLength),
            CryptoAlgorithm.Ctr => NativeOpenClMethods.AesCtrDecryptAlloc(key, (nuint)key.Length, iv16, (int)padding, input, (nuint)input.Length, out outputPointer, out outputLength),
            CryptoAlgorithm.Gcm when encrypt => EncryptOpenClGcm(key, iv12, aad, input, out outputPointer, out outputLength, out tag),
            CryptoAlgorithm.Gcm => DecryptOpenClGcm(key, iv12, aad, input, providedTag, out outputPointer, out outputLength),
            _ => throw new NotSupportedException($"Unsupported OpenCL algorithm: {algorithm}.")
        };

        return CopyAndFree(outputPointer, outputLength, status, NativeOpenClMethods.Free, "OpenCL");
    }

    private static void ExecuteCpuDiscard(bool encrypt, CryptoAlgorithm algorithm, CryptoPaddingMode padding, byte[] key, byte[] iv16, byte[] iv12, byte[] aad, byte[] input, byte[] providedTag, out byte[] tag)
    {
        nint outputPointer = 0;
        nuint outputLength = 0;
        tag = Array.Empty<byte>();

        var status = algorithm switch
        {
            CryptoAlgorithm.Cbc when encrypt => NativeCpuMethods.AesCbcEncryptAlloc(key, (nuint)key.Length, iv16, (int)padding, input, (nuint)input.Length, out outputPointer, out outputLength),
            CryptoAlgorithm.Cbc => NativeCpuMethods.AesCbcDecryptAlloc(key, (nuint)key.Length, iv16, (int)padding, input, (nuint)input.Length, out outputPointer, out outputLength),
            CryptoAlgorithm.Ctr when encrypt => NativeCpuMethods.AesCtrEncryptAlloc(key, (nuint)key.Length, iv16, (int)padding, input, (nuint)input.Length, out outputPointer, out outputLength),
            CryptoAlgorithm.Ctr => NativeCpuMethods.AesCtrDecryptAlloc(key, (nuint)key.Length, iv16, (int)padding, input, (nuint)input.Length, out outputPointer, out outputLength),
            CryptoAlgorithm.Gcm when encrypt => EncryptCpuGcm(key, iv12, aad, input, out outputPointer, out outputLength, out tag),
            CryptoAlgorithm.Gcm => DecryptCpuGcm(key, iv12, aad, input, providedTag, out outputPointer, out outputLength),
            _ => throw new NotSupportedException($"Unsupported CPU algorithm: {algorithm}.")
        };

        HandleStatusAndFree(outputPointer, status, NativeCpuMethods.Free, "native CPU");
    }

    private static void ExecuteOpenClDiscard(bool encrypt, CryptoAlgorithm algorithm, CryptoPaddingMode padding, byte[] key, byte[] iv16, byte[] iv12, byte[] aad, byte[] input, byte[] providedTag, out byte[] tag)
    {
        nint outputPointer = 0;
        nuint outputLength = 0;
        tag = Array.Empty<byte>();

        var status = algorithm switch
        {
            CryptoAlgorithm.Ctr when encrypt => NativeOpenClMethods.AesCtrEncryptAlloc(key, (nuint)key.Length, iv16, (int)padding, input, (nuint)input.Length, out outputPointer, out outputLength),
            CryptoAlgorithm.Ctr => NativeOpenClMethods.AesCtrDecryptAlloc(key, (nuint)key.Length, iv16, (int)padding, input, (nuint)input.Length, out outputPointer, out outputLength),
            CryptoAlgorithm.Gcm when encrypt => EncryptOpenClGcm(key, iv12, aad, input, out outputPointer, out outputLength, out tag),
            CryptoAlgorithm.Gcm => DecryptOpenClGcm(key, iv12, aad, input, providedTag, out outputPointer, out outputLength),
            _ => throw new NotSupportedException($"Unsupported OpenCL algorithm: {algorithm}.")
        };

        HandleStatusAndFree(outputPointer, status, NativeOpenClMethods.Free, "OpenCL");
    }

    private static NativeStatus EncryptCpuGcm(byte[] key, byte[] iv12, byte[] aad, byte[] input, out nint outputPointer, out nuint outputLength, out byte[] tag)
    {
        tag = new byte[16];
        return NativeCpuMethods.AesGcmEncryptAlloc(key, (nuint)key.Length, iv12, (nuint)iv12.Length, aad, (nuint)aad.Length, input, (nuint)input.Length, out outputPointer, out outputLength, tag);
    }

    private static NativeStatus DecryptCpuGcm(byte[] key, byte[] iv12, byte[] aad, byte[] input, byte[] providedTag, out nint outputPointer, out nuint outputLength)
    {
        if (providedTag.Length != 16)
        {
            throw new ArgumentException("GCM requires a 16-byte authentication tag.", nameof(providedTag));
        }

        return NativeCpuMethods.AesGcmDecryptAlloc(key, (nuint)key.Length, iv12, (nuint)iv12.Length, aad, (nuint)aad.Length, input, (nuint)input.Length, providedTag, out outputPointer, out outputLength);
    }

    private static NativeStatus EncryptOpenClGcm(byte[] key, byte[] iv12, byte[] aad, byte[] input, out nint outputPointer, out nuint outputLength, out byte[] tag)
    {
        tag = new byte[16];
        return NativeOpenClMethods.AesGcmEncryptAlloc(key, (nuint)key.Length, iv12, (nuint)iv12.Length, aad, (nuint)aad.Length, input, (nuint)input.Length, out outputPointer, out outputLength, tag);
    }

    private static NativeStatus DecryptOpenClGcm(byte[] key, byte[] iv12, byte[] aad, byte[] input, byte[] providedTag, out nint outputPointer, out nuint outputLength)
    {
        if (providedTag.Length != 16)
        {
            throw new ArgumentException("GCM requires a 16-byte authentication tag.", nameof(providedTag));
        }

        return NativeOpenClMethods.AesGcmDecryptAlloc(key, (nuint)key.Length, iv12, (nuint)iv12.Length, aad, (nuint)aad.Length, input, (nuint)input.Length, providedTag, out outputPointer, out outputLength);
    }

    private static NativeStatus EncryptCpuGcmFile(byte[] key, byte[] iv, byte[] aad, string inputPath, string outputPath, out byte[] tag)
    {
        tag = new byte[16];
        return NativeCpuMethods.AesGcmEncryptFile(key, (nuint)key.Length, iv, (nuint)iv.Length, aad, (nuint)aad.Length, inputPath, outputPath, tag);
    }

    private static NativeStatus DecryptCpuGcmFile(byte[] key, byte[] iv, byte[] aad, string inputPath, string outputPath, byte[] providedTag)
    {
        if (providedTag.Length != 16)
        {
            throw new ArgumentException("GCM requires a 16-byte authentication tag.", nameof(providedTag));
        }

        return NativeCpuMethods.AesGcmDecryptFile(key, (nuint)key.Length, iv, (nuint)iv.Length, aad, (nuint)aad.Length, inputPath, outputPath, providedTag);
    }

    private static NativeStatus EncryptOpenClGcmFile(byte[] key, byte[] iv, byte[] aad, string inputPath, string outputPath, out byte[] tag)
    {
        tag = new byte[16];
        return NativeOpenClMethods.AesGcmEncryptFile(key, (nuint)key.Length, iv, (nuint)iv.Length, aad, (nuint)aad.Length, inputPath, outputPath, tag);
    }

    private static NativeStatus DecryptOpenClGcmFile(byte[] key, byte[] iv, byte[] aad, string inputPath, string outputPath, byte[] providedTag)
    {
        if (providedTag.Length != 16)
        {
            throw new ArgumentException("GCM requires a 16-byte authentication tag.", nameof(providedTag));
        }

        return NativeOpenClMethods.AesGcmDecryptFile(key, (nuint)key.Length, iv, (nuint)iv.Length, aad, (nuint)aad.Length, inputPath, outputPath, providedTag);
    }

    private static void HandleStatusAndFree(nint pointer, NativeStatus status, Action<nint> freeAction, string engineName)
    {
        try
        {
            if (status != NativeStatus.Ok)
            {
                throw new InvalidOperationException($"The {engineName} operation failed with status {(int)status} ({status}).");
            }
        }
        finally
        {
            if (pointer != 0)
            {
                freeAction(pointer);
            }
        }
    }

    private static byte[] CopyAndFree(nint pointer, nuint length, NativeStatus status, Action<nint> freeAction, string engineName)
    {
        if (status != NativeStatus.Ok)
        {
            if (pointer != 0)
            {
                freeAction(pointer);
            }

            throw new InvalidOperationException($"The {engineName} operation failed with status {(int)status} ({status}).");
        }

        try
        {
            if (length == 0)
            {
                return Array.Empty<byte>();
            }

            var managed = new byte[(int)length];
            Marshal.Copy(pointer, managed, 0, managed.Length);
            return managed;
        }
        finally
        {
            if (pointer != 0)
            {
                freeAction(pointer);
            }
        }
    }

    private static string GetOpenClErrorMessage(NativeStatus? status)
    {
        var messagePointer = NativeOpenClMethods.LastErrorMessage();
        var nativeMessage = messagePointer == 0 ? string.Empty : Marshal.PtrToStringAnsi(messagePointer) ?? string.Empty;
        if (string.IsNullOrWhiteSpace(nativeMessage))
        {
            return status is null ? "OpenCL did not provide any additional details." : $"status {(int)status.Value} ({status.Value})";
        }

        return status is null ? nativeMessage : $"status {(int)status.Value} ({status.Value}): {nativeMessage}";
    }
}
