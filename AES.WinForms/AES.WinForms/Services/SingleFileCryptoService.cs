using System.Text;
using AES.WinForms.Models;
using AES.WinForms.Native;

namespace AES.WinForms.Services;

public sealed class SingleFileCryptoService
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("AESUIF01");
    private readonly PasswordDerivationService _passwordDerivationService;
    private readonly NativeCryptoFacade _nativeCryptoFacade;

    public SingleFileCryptoService(PasswordDerivationService passwordDerivationService, NativeCryptoFacade nativeCryptoFacade)
    {
        _passwordDerivationService = passwordDerivationService;
        _nativeCryptoFacade = nativeCryptoFacade;
    }

    public Task<string> ExecuteAsync(SingleFileRequest request, CancellationToken cancellationToken = default)
    {
        return Task.Run(() => Execute(request, cancellationToken), cancellationToken);
    }

    public OperationResult<SingleFilePackageInfo> TryReadPackage(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return OperationResult<SingleFilePackageInfo>.Failure("Select an encrypted input file first.");
            }

            if (!File.Exists(path))
            {
                return OperationResult<SingleFilePackageInfo>.Failure("The selected encrypted input file does not exist.");
            }

            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
            var package = ReadHeader(reader, stream.Length);
            return OperationResult<SingleFilePackageInfo>.Success(package);
        }
        catch (Exception ex)
        {
            return OperationResult<SingleFilePackageInfo>.Failure(ex.Message);
        }
    }

    private string Execute(SingleFileRequest request, CancellationToken cancellationToken)
    {
        ValidateRequest(request);
        cancellationToken.ThrowIfCancellationRequested();
        return request.Encrypt ? EncryptFile(request, cancellationToken) : DecryptFile(request, cancellationToken);
    }

    private string EncryptFile(SingleFileRequest request, CancellationToken cancellationToken)
    {
        var salt = _passwordDerivationService.CreateRandomBytes(16);
        var key = _passwordDerivationService.DeriveKey(request.Password, salt, request.KeySizeBits);
        var iv = request.Algorithm == CryptoAlgorithm.Gcm
            ? _passwordDerivationService.CreateRandomBytes(12)
            : _passwordDerivationService.CreateRandomBytes(16);
        var padding = request.Algorithm == CryptoAlgorithm.Gcm ? CryptoPaddingMode.None : request.Padding;
        var tempOutputPath = CreateTemporaryFilePath();
        var tempPayloadPath = CreateTemporaryFilePath();

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            var tag = _nativeCryptoFacade.EncryptFile(request.Engine, request.Algorithm, padding, key, iv, Array.Empty<byte>(), request.InputPath, tempPayloadPath);
            using (var outputStream = new FileStream(tempOutputPath, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var writer = new BinaryWriter(outputStream, Encoding.UTF8, leaveOpen: true))
            using (var payloadStream = new FileStream(tempPayloadPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                WriteHeader(writer, new SingleFilePackageInfo
                {
                    Algorithm = request.Algorithm,
                    Padding = padding,
                    KeySizeBits = request.KeySizeBits,
                    IterationCount = PasswordDerivationService.DefaultIterationCount,
                    Salt = salt,
                    Iv = iv,
                    Tag = tag
                });
                payloadStream.CopyTo(outputStream);
                writer.Flush();
                outputStream.Flush(true);
            }

            cancellationToken.ThrowIfCancellationRequested();
            FinalizeOutputFile(tempOutputPath, request.OutputPath);
            return $"Encryption completed successfully. Output written to {request.OutputPath}.";
        }
        catch
        {
            DeleteIfExists(tempOutputPath);
            throw;
        }
        finally
        {
            DeleteIfExists(tempPayloadPath);
        }
    }

    private string DecryptFile(SingleFileRequest request, CancellationToken cancellationToken)
    {
        var package = ReadPackage(request.InputPath);
        var key = _passwordDerivationService.DeriveKey(request.Password, package.Salt, package.KeySizeBits, package.IterationCount);
        var tempOutputPath = CreateTemporaryFilePath();
        var tempPayloadPath = CreateTemporaryFilePath();

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (var inputStream = new FileStream(request.InputPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var payloadStream = new FileStream(tempPayloadPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                inputStream.Position = package.PayloadOffset;
                inputStream.CopyTo(payloadStream);
            }

            _nativeCryptoFacade.DecryptFile(request.Engine, package.Algorithm, package.Padding, key, package.Iv, Array.Empty<byte>(), tempPayloadPath, tempOutputPath, package.Tag);

            cancellationToken.ThrowIfCancellationRequested();
            FinalizeOutputFile(tempOutputPath, request.OutputPath);
            return $"Decryption completed successfully. Output written to {request.OutputPath}.";
        }
        catch
        {
            DeleteIfExists(tempOutputPath);
            throw;
        }
        finally
        {
            DeleteIfExists(tempPayloadPath);
        }
    }

    private SingleFilePackageInfo ReadPackage(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
        return ReadHeader(reader, stream.Length);
    }

    private static SingleFilePackageInfo ReadHeader(BinaryReader reader, long fileLength)
    {
        var magic = reader.ReadBytes(Magic.Length);
        if (!magic.SequenceEqual(Magic))
        {
            throw new InvalidDataException("The selected input file does not contain a valid AES UI package header.");
        }

        var headerVersion = reader.ReadByte();
        if (headerVersion != 1)
        {
            throw new InvalidDataException($"Unsupported AES UI package version: {headerVersion}.");
        }

        var algorithm = (CryptoAlgorithm)reader.ReadByte();
        var padding = (CryptoPaddingMode)reader.ReadByte();
        var keySizeBits = reader.ReadUInt16();
        var iterationCount = reader.ReadInt32();
        var saltLength = reader.ReadByte();
        var ivLength = reader.ReadByte();
        var tagLength = reader.ReadByte();
        var salt = reader.ReadBytes(saltLength);
        var iv = reader.ReadBytes(ivLength);
        var tag = reader.ReadBytes(tagLength);

        if (salt.Length != saltLength || iv.Length != ivLength || tag.Length != tagLength)
        {
            throw new InvalidDataException("The encrypted package header is truncated.");
        }

        if (algorithm is not (CryptoAlgorithm.Cbc or CryptoAlgorithm.Ctr or CryptoAlgorithm.Gcm))
        {
            throw new InvalidDataException("The encrypted package references an unknown algorithm.");
        }

        if (padding is not (CryptoPaddingMode.Pkcs7 or CryptoPaddingMode.AnsiX923 or CryptoPaddingMode.Iso7816_4 or CryptoPaddingMode.Zero or CryptoPaddingMode.None))
        {
            throw new InvalidDataException("The encrypted package references an unknown padding mode.");
        }

        if (keySizeBits is not (128 or 192 or 256))
        {
            throw new InvalidDataException("The encrypted package references an unsupported key size.");
        }

        if (iterationCount <= 0)
        {
            throw new InvalidDataException("The encrypted package references an invalid PBKDF2 iteration count.");
        }

        if (saltLength == 0)
        {
            throw new InvalidDataException("The encrypted package is missing its key derivation salt.");
        }

        if (algorithm == CryptoAlgorithm.Gcm)
        {
            if (padding != CryptoPaddingMode.None)
            {
                throw new InvalidDataException("AES-GCM packages must use the None padding mode.");
            }

            if (ivLength != 12)
            {
                throw new InvalidDataException("AES-GCM packages must contain a 12-byte IV.");
            }

            if (tagLength != 16)
            {
                throw new InvalidDataException("AES-GCM packages must contain a 16-byte authentication tag.");
            }
        }
        else
        {
            if (ivLength != 16)
            {
                throw new InvalidDataException("CBC and CTR packages must contain a 16-byte IV.");
            }

            if (tagLength != 0)
            {
                throw new InvalidDataException("CBC and CTR packages must not contain an authentication tag.");
            }
        }

        var payloadOffset = reader.BaseStream.Position;
        if (payloadOffset > fileLength)
        {
            throw new InvalidDataException("The encrypted package header points past the end of the file.");
        }

        return new SingleFilePackageInfo
        {
            Algorithm = algorithm,
            Padding = padding,
            KeySizeBits = keySizeBits,
            IterationCount = iterationCount,
            Salt = salt,
            Iv = iv,
            Tag = tag,
            PayloadOffset = payloadOffset,
            PayloadLength = fileLength - payloadOffset
        };
    }

    private static void WriteHeader(BinaryWriter writer, SingleFilePackageInfo package)
    {
        writer.Write(Magic);
        writer.Write((byte)1);
        writer.Write((byte)package.Algorithm);
        writer.Write((byte)package.Padding);
        writer.Write((ushort)package.KeySizeBits);
        writer.Write(package.IterationCount);
        writer.Write((byte)package.Salt.Length);
        writer.Write((byte)package.Iv.Length);
        writer.Write((byte)package.Tag.Length);
        writer.Write(package.Salt);
        writer.Write(package.Iv);
        writer.Write(package.Tag);
    }

    private static void ValidateRequest(SingleFileRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.InputPath))
        {
            throw new InvalidOperationException("Select an input file first.");
        }

        if (!File.Exists(request.InputPath))
        {
            throw new FileNotFoundException("The selected input file does not exist.", request.InputPath);
        }

        if (string.IsNullOrWhiteSpace(request.OutputPath))
        {
            throw new InvalidOperationException("Select an output file first.");
        }

        if (string.Equals(Path.GetFullPath(request.InputPath), Path.GetFullPath(request.OutputPath), StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The input file and the output file must be different.");
        }

        if (string.IsNullOrWhiteSpace(request.Password))
        {
            throw new InvalidOperationException("Enter a password first.");
        }
    }


    private static string CreateTemporaryFilePath()
    {
        return Path.Combine(Path.GetTempPath(), $"aes-ui-{Guid.NewGuid():N}.tmp");
    }

    private static void FinalizeOutputFile(string temporaryPath, string destinationPath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(destinationPath) ?? AppContext.BaseDirectory);
        if (File.Exists(destinationPath))
        {
            File.Delete(destinationPath);
        }

        File.Move(temporaryPath, destinationPath);
    }

    private static void DeleteIfExists(string? path)
    {
        if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
        {
            File.Delete(path);
        }
    }
}
