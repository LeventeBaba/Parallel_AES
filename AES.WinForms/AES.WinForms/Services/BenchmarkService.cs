using System.Diagnostics;
using System.Runtime;
using System.Runtime.InteropServices;
using AES.WinForms.Models;
using AES.WinForms.Native;

namespace AES.WinForms.Services;

public sealed class BenchmarkService
{
    private readonly PasswordDerivationService _passwordDerivationService;
    private readonly ManagedCryptoService _managedCryptoService;
    private readonly NativeCryptoFacade _nativeCryptoFacade;
    private readonly EnvironmentInspectionService _environmentInspectionService;

    public BenchmarkService(PasswordDerivationService passwordDerivationService, ManagedCryptoService managedCryptoService, NativeCryptoFacade nativeCryptoFacade, EnvironmentInspectionService environmentInspectionService)
    {
        _passwordDerivationService = passwordDerivationService;
        _managedCryptoService = managedCryptoService;
        _nativeCryptoFacade = nativeCryptoFacade;
        _environmentInspectionService = environmentInspectionService;
    }


    private sealed class DecryptPreparation
    {
        public required byte[] Ciphertext { get; init; }
        public required byte[] Tag { get; init; }
        public required int PlaintextLength { get; init; }
        public required CryptoEngine PreparationEngine { get; init; }
    }

    public Task<BenchmarkSession> RunAsync(BenchmarkRequest request, IProgress<string>? progress, CancellationToken cancellationToken)
    {
        return Task.Run(() => Run(request, progress, cancellationToken), cancellationToken);
    }

    private BenchmarkSession Run(BenchmarkRequest request, IProgress<string>? progress, CancellationToken cancellationToken)
    {
        ValidateRequest(request);

        var sessionId = Guid.NewGuid();
        var createdUtc = DateTimeOffset.UtcNow;
        var salt = _passwordDerivationService.CreateRandomBytes(16);
        var iv16 = _passwordDerivationService.CreateRandomBytes(16);
        var iv12 = _passwordDerivationService.CreateRandomBytes(12);
        var aad = _passwordDerivationService.CreateRandomBytes(16);
        var key = _passwordDerivationService.DeriveKey(request.Password, salt, request.KeySizeBits);
        var rows = new List<BenchmarkResultRow>();
        var environmentInfo = _environmentInspectionService.CollectBenchmarkEnvironmentInfo();
        var environmentDescription = _environmentInspectionService.BuildEnvironmentDescription(environmentInfo);

        progress?.Report("Preparing benchmark payload...");

        if (request.WarmupBeforeRun)
        {
            progress?.Report("Running warmup phase...");
            var warmupMegabytes = Math.Clamp(Math.Min(request.DataSizeMegabytes, 8), 1, 8);
            var warmupPlaintext = CreateRandomPayload(warmupMegabytes);
            RunWarmup(request, key, iv16, iv12, aad, warmupPlaintext);
            warmupPlaintext = Array.Empty<byte>();
            ForceCollectionIfNeeded(request);
        }

        for (var iteration = 1; iteration <= request.IterationCount; iteration++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            progress?.Report($"Running iteration {iteration} of {request.IterationCount}...");

            var encryptPayload = CreateRandomPayload(request.DataSizeMegabytes);
            rows.Add(RunNativeCpuEncrypt(sessionId, createdUtc, request, key, iv16, iv12, aad, encryptPayload, iteration));
            ForceCollectionIfNeeded(request);
            rows.Add(RunOpenClEncrypt(sessionId, createdUtc, request, key, iv16, iv12, aad, encryptPayload, iteration));
            ForceCollectionIfNeeded(request);
            rows.Add(RunManagedEncrypt(sessionId, createdUtc, request, key, iv16, iv12, aad, encryptPayload, iteration));
            ForceCollectionIfNeeded(request);

            DecryptPreparation? decryptPreparation = null;
            try
            {
                decryptPreparation = PrepareDecryptInput(request, key, iv16, iv12, aad, encryptPayload);
            }
            catch (Exception ex)
            {
                var note = $"Failed to prepare shared decrypt input: {ex.Message}";
                if (request.Algorithm == CryptoAlgorithm.Gcm)
                {
                    note += " This is usually caused by memory pressure in the 32-bit benchmark process.";
                }

                rows.Add(CreateFailureRow(sessionId, createdUtc, request, encryptPayload.Length, 0, iteration, CryptoEngine.NativeCpu, BenchmarkDirection.Decrypt, note));
                rows.Add(CreateFailureRow(sessionId, createdUtc, request, encryptPayload.Length, 0, iteration, CryptoEngine.OpenCl, BenchmarkDirection.Decrypt, note));
                rows.Add(CreateFailureRow(sessionId, createdUtc, request, encryptPayload.Length, 0, iteration, CryptoEngine.ManagedAes, BenchmarkDirection.Decrypt, note));
            }

            encryptPayload = Array.Empty<byte>();
            ForceCollectionIfNeeded(request);

            if (decryptPreparation is not null)
            {
                rows.Add(RunNativeCpuDecrypt(sessionId, createdUtc, request, key, iv16, iv12, aad, decryptPreparation, iteration));
                ForceCollectionIfNeeded(request);
                rows.Add(RunOpenClDecrypt(sessionId, createdUtc, request, key, iv16, iv12, aad, decryptPreparation, iteration));
                ForceCollectionIfNeeded(request);
                rows.Add(RunManagedDecrypt(sessionId, createdUtc, request, key, iv16, iv12, aad, decryptPreparation, iteration));
                decryptPreparation = null;
                ForceCollectionIfNeeded(request);
            }
        }

        var summaries = BuildSummaries(rows);
        ApplyRelativeMetrics(rows, summaries);

        return new BenchmarkSession
        {
            SessionId = sessionId,
            CreatedUtc = createdUtc,
            Request = request,
            SaltBase64 = Convert.ToBase64String(salt),
            Iv16Base64 = Convert.ToBase64String(iv16),
            Iv12Base64 = Convert.ToBase64String(iv12),
            AadBase64 = Convert.ToBase64String(aad),
            Rows = rows,
            Summaries = summaries,
            EnvironmentInfo = environmentInfo,
            EnvironmentDescription = environmentDescription,
            Notes = BuildNotes(request)
        };
    }

    private void RunWarmup(BenchmarkRequest request, byte[] key, byte[] iv16, byte[] iv12, byte[] aad, byte[] plaintext)
    {
        TryRun(() =>
        {
            if (_nativeCryptoFacade.IsSupported(CryptoEngine.OpenCl, request.Algorithm))
            {
                _nativeCryptoFacade.TryWarmupOpenCl(out _);
            }
        });

        TryRun(() =>
        {
            if (_nativeCryptoFacade.IsSupported(CryptoEngine.NativeCpu, request.Algorithm))
            {
                var encrypted = _nativeCryptoFacade.Encrypt(CryptoEngine.NativeCpu, request.Algorithm, request.Padding, key, iv16, iv12, aad, plaintext, out var tag);
                _nativeCryptoFacade.Decrypt(CryptoEngine.NativeCpu, request.Algorithm, request.Padding, key, iv16, iv12, aad, encrypted, tag);
            }
        });

        TryRun(() =>
        {
            if (_nativeCryptoFacade.IsSupported(CryptoEngine.OpenCl, request.Algorithm))
            {
                var encrypted = _nativeCryptoFacade.Encrypt(CryptoEngine.OpenCl, request.Algorithm, request.Padding, key, iv16, iv12, aad, plaintext, out var tag);
                _nativeCryptoFacade.Decrypt(CryptoEngine.OpenCl, request.Algorithm, request.Padding, key, iv16, iv12, aad, encrypted, tag);
            }
        });

        TryRun(() =>
        {
            if (_managedCryptoService.IsSupported(request.Algorithm, request.Padding))
            {
                var encrypted = _managedCryptoService.Encrypt(request.Algorithm, request.Padding, key, iv16, iv12, aad, plaintext, out var tag);
                _managedCryptoService.Decrypt(request.Algorithm, request.Padding, key, iv16, iv12, aad, encrypted, tag);
            }
        });
    }

    private static void TryRun(Action action)
    {
        try
        {
            action();
        }
        catch
        {
        }
    }

    private BenchmarkResultRow RunNativeCpuEncrypt(Guid sessionId, DateTimeOffset timestampUtc, BenchmarkRequest request, byte[] key, byte[] iv16, byte[] iv12, byte[] aad, byte[] plaintext, int iteration)
    {
        return RunEngine(
            sessionId,
            timestampUtc,
            request,
            plaintext.Length,
            EstimateOutputLength(request.Algorithm, request.Padding, plaintext.Length),
            iteration,
            CryptoEngine.NativeCpu,
            BenchmarkDirection.Encrypt,
            () => { _nativeCryptoFacade.EncryptAndDiscard(CryptoEngine.NativeCpu, request.Algorithm, request.Padding, key, iv16, iv12, aad, plaintext, out _); });
    }

    private BenchmarkResultRow RunNativeCpuDecrypt(Guid sessionId, DateTimeOffset timestampUtc, BenchmarkRequest request, byte[] key, byte[] iv16, byte[] iv12, byte[] aad, DecryptPreparation decryptPreparation, int iteration)
    {
        return RunEngine(
            sessionId,
            timestampUtc,
            request,
            decryptPreparation.Ciphertext.Length,
            decryptPreparation.PlaintextLength,
            iteration,
            CryptoEngine.NativeCpu,
            BenchmarkDirection.Decrypt,
            () => { _nativeCryptoFacade.DecryptAndDiscard(CryptoEngine.NativeCpu, request.Algorithm, request.Padding, key, iv16, iv12, aad, decryptPreparation.Ciphertext, decryptPreparation.Tag); });
    }

    private BenchmarkResultRow RunOpenClEncrypt(Guid sessionId, DateTimeOffset timestampUtc, BenchmarkRequest request, byte[] key, byte[] iv16, byte[] iv12, byte[] aad, byte[] plaintext, int iteration)
    {
        if (!_nativeCryptoFacade.IsSupported(CryptoEngine.OpenCl, request.Algorithm))
        {
            return CreateFailureRow(sessionId, timestampUtc, request, plaintext.Length, 0, iteration, CryptoEngine.OpenCl, BenchmarkDirection.Encrypt, "The selected algorithm is not implemented in the OpenCL FFI yet.");
        }

        return RunEngine(
            sessionId,
            timestampUtc,
            request,
            plaintext.Length,
            EstimateOutputLength(request.Algorithm, request.Padding, plaintext.Length),
            iteration,
            CryptoEngine.OpenCl,
            BenchmarkDirection.Encrypt,
            () => { _nativeCryptoFacade.EncryptAndDiscard(CryptoEngine.OpenCl, request.Algorithm, request.Padding, key, iv16, iv12, aad, plaintext, out _); });
    }

    private BenchmarkResultRow RunOpenClDecrypt(Guid sessionId, DateTimeOffset timestampUtc, BenchmarkRequest request, byte[] key, byte[] iv16, byte[] iv12, byte[] aad, DecryptPreparation decryptPreparation, int iteration)
    {
        if (!_nativeCryptoFacade.IsSupported(CryptoEngine.OpenCl, request.Algorithm))
        {
            return CreateFailureRow(sessionId, timestampUtc, request, decryptPreparation.Ciphertext.Length, 0, iteration, CryptoEngine.OpenCl, BenchmarkDirection.Decrypt, "The selected algorithm is not implemented in the OpenCL FFI yet.");
        }

        return RunEngine(
            sessionId,
            timestampUtc,
            request,
            decryptPreparation.Ciphertext.Length,
            decryptPreparation.PlaintextLength,
            iteration,
            CryptoEngine.OpenCl,
            BenchmarkDirection.Decrypt,
            () => { _nativeCryptoFacade.DecryptAndDiscard(CryptoEngine.OpenCl, request.Algorithm, request.Padding, key, iv16, iv12, aad, decryptPreparation.Ciphertext, decryptPreparation.Tag); });
    }

    private BenchmarkResultRow RunManagedEncrypt(Guid sessionId, DateTimeOffset timestampUtc, BenchmarkRequest request, byte[] key, byte[] iv16, byte[] iv12, byte[] aad, byte[] plaintext, int iteration)
    {
        if (!_managedCryptoService.IsSupported(request.Algorithm, request.Padding))
        {
            return CreateFailureRow(sessionId, timestampUtc, request, plaintext.Length, 0, iteration, CryptoEngine.ManagedAes, BenchmarkDirection.Encrypt, "Managed AES does not support this algorithm and padding combination.");
        }

        return RunEngine(
            sessionId,
            timestampUtc,
            request,
            plaintext.Length,
            EstimateOutputLength(request.Algorithm, request.Padding, plaintext.Length),
            iteration,
            CryptoEngine.ManagedAes,
            BenchmarkDirection.Encrypt,
            () => { _managedCryptoService.Encrypt(request.Algorithm, request.Padding, key, iv16, iv12, aad, plaintext, out _); });
    }

    private BenchmarkResultRow RunManagedDecrypt(Guid sessionId, DateTimeOffset timestampUtc, BenchmarkRequest request, byte[] key, byte[] iv16, byte[] iv12, byte[] aad, DecryptPreparation decryptPreparation, int iteration)
    {
        if (!_managedCryptoService.IsSupported(request.Algorithm, request.Padding))
        {
            return CreateFailureRow(sessionId, timestampUtc, request, decryptPreparation.Ciphertext.Length, 0, iteration, CryptoEngine.ManagedAes, BenchmarkDirection.Decrypt, "Managed AES does not support this algorithm and padding combination.");
        }

        return RunEngine(
            sessionId,
            timestampUtc,
            request,
            decryptPreparation.Ciphertext.Length,
            decryptPreparation.PlaintextLength,
            iteration,
            CryptoEngine.ManagedAes,
            BenchmarkDirection.Decrypt,
            () => { _managedCryptoService.Decrypt(request.Algorithm, request.Padding, key, iv16, iv12, aad, decryptPreparation.Ciphertext, decryptPreparation.Tag); });
    }

    private DecryptPreparation PrepareDecryptInput(BenchmarkRequest request, byte[] key, byte[] iv16, byte[] iv12, byte[] aad, byte[] plaintext)
    {
        if (_managedCryptoService.IsSupported(request.Algorithm, request.Padding))
        {
            var ciphertext = _managedCryptoService.Encrypt(request.Algorithm, request.Padding, key, iv16, iv12, aad, plaintext, out var tag);
            return new DecryptPreparation
            {
                Ciphertext = ciphertext,
                Tag = tag,
                PlaintextLength = plaintext.Length,
                PreparationEngine = CryptoEngine.ManagedAes
            };
        }

        if (_nativeCryptoFacade.IsSupported(CryptoEngine.NativeCpu, request.Algorithm))
        {
            var ciphertext = _nativeCryptoFacade.Encrypt(CryptoEngine.NativeCpu, request.Algorithm, request.Padding, key, iv16, iv12, aad, plaintext, out var tag);
            return new DecryptPreparation
            {
                Ciphertext = ciphertext,
                Tag = tag,
                PlaintextLength = plaintext.Length,
                PreparationEngine = CryptoEngine.NativeCpu
            };
        }

        if (_nativeCryptoFacade.IsSupported(CryptoEngine.OpenCl, request.Algorithm))
        {
            var ciphertext = _nativeCryptoFacade.Encrypt(CryptoEngine.OpenCl, request.Algorithm, request.Padding, key, iv16, iv12, aad, plaintext, out var tag);
            return new DecryptPreparation
            {
                Ciphertext = ciphertext,
                Tag = tag,
                PlaintextLength = plaintext.Length,
                PreparationEngine = CryptoEngine.OpenCl
            };
        }

        throw new NotSupportedException("No compatible engine is available to prepare decrypt input for the selected algorithm.");
    }

    private BenchmarkResultRow RunEngine(Guid sessionId, DateTimeOffset timestampUtc, BenchmarkRequest request, int inputBytes, int outputBytes, int iteration, CryptoEngine engine, BenchmarkDirection direction, Action execute)
    {
        try
        {
            var stopwatch = Stopwatch.StartNew();
            execute();
            stopwatch.Stop();

            var elapsedMs = Math.Max(stopwatch.Elapsed.TotalMilliseconds, 0.0001d);
            return new BenchmarkResultRow
            {
                SessionId = sessionId,
                TimestampUtc = timestampUtc,
                Iteration = iteration,
                Algorithm = request.Algorithm,
                Padding = request.Padding,
                KeySizeBits = request.KeySizeBits,
                InputBytes = inputBytes,
                OutputBytes = outputBytes,
                Engine = engine,
                Direction = direction,
                ElapsedMilliseconds = elapsedMs,
                ThroughputMegabytesPerSecond = (inputBytes / 1024d / 1024d) / (elapsedMs / 1000d),
                Succeeded = true
            };
        }
        catch (DllNotFoundException ex)
        {
            return CreateFailureRow(sessionId, timestampUtc, request, inputBytes, 0, iteration, engine, direction, $"Native dependency not found: {ex.Message}");
        }
        catch (BadImageFormatException ex)
        {
            return CreateFailureRow(sessionId, timestampUtc, request, inputBytes, 0, iteration, engine, direction, $"Native dependency architecture mismatch: {ex.Message}");
        }
        catch (EntryPointNotFoundException ex)
        {
            return CreateFailureRow(sessionId, timestampUtc, request, inputBytes, 0, iteration, engine, direction, $"Required native export is missing: {ex.Message}");
        }
        catch (Exception ex)
        {
            var note = engine == CryptoEngine.OpenCl ? BuildDetailedOpenClNote(ex.Message) : ex.Message;
            return CreateFailureRow(sessionId, timestampUtc, request, inputBytes, 0, iteration, engine, direction, note);
        }
    }

    private BenchmarkResultRow CreateFailureRow(Guid sessionId, DateTimeOffset timestampUtc, BenchmarkRequest request, int inputBytes, int outputBytes, int iteration, CryptoEngine engine, BenchmarkDirection direction, string note)
    {
        return new BenchmarkResultRow
        {
            SessionId = sessionId,
            TimestampUtc = timestampUtc,
            Iteration = iteration,
            Algorithm = request.Algorithm,
            Padding = request.Padding,
            KeySizeBits = request.KeySizeBits,
            InputBytes = inputBytes,
            OutputBytes = outputBytes,
            Engine = engine,
            Direction = direction,
            ElapsedMilliseconds = 0,
            ThroughputMegabytesPerSecond = 0,
            Succeeded = false,
            Note = note
        };
    }

    private string BuildDetailedOpenClNote(string baseMessage)
    {
        var detail = _nativeCryptoFacade.GetOpenClLastErrorMessage();
        if (string.IsNullOrWhiteSpace(detail) || baseMessage.Contains(detail, StringComparison.Ordinal))
        {
            return baseMessage;
        }

        return $"{baseMessage} | {detail}";
    }

    private static byte[] CreateRandomPayload(int dataSizeMegabytes)
    {
        var payload = new byte[dataSizeMegabytes * 1024 * 1024];
        Random.Shared.NextBytes(payload);
        return payload;
    }

    private static void ForceCollectionIfNeeded(BenchmarkRequest request)
    {
        if (RuntimeInformation.ProcessArchitecture != Architecture.X86 || request.DataSizeMegabytes < 64)
        {
            return;
        }

        GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
    }

    private static void ValidateRequest(BenchmarkRequest request)
    {
        if (request.DataSizeMegabytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request.DataSizeMegabytes), "The generated data size must be larger than zero.");
        }

        if (request.IterationCount <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request.IterationCount), "The iteration count must be larger than zero.");
        }

        if (request.KeySizeBits is not (128 or 192 or 256))
        {
            throw new ArgumentOutOfRangeException(nameof(request.KeySizeBits), "The key size must be 128, 192, or 256 bits.");
        }
    }

    private static int EstimateOutputLength(CryptoAlgorithm algorithm, CryptoPaddingMode padding, int inputBytes)
    {
        if (algorithm == CryptoAlgorithm.Gcm)
        {
            return inputBytes;
        }

        if (padding == CryptoPaddingMode.None)
        {
            return inputBytes;
        }

        if (padding == CryptoPaddingMode.Zero && inputBytes % 16 == 0)
        {
            return inputBytes;
        }

        return ((inputBytes / 16) + 1) * 16;
    }


    private static string BuildNotes(BenchmarkRequest request)
    {
        var parts = new List<string>
        {
            "The benchmark compares the native sequential AES, the OpenCL-parallel AES, and managed .NET AES when the selected combination is available.",
            "Speed-up is reported only for the OpenCL-parallel AES relative to the native sequential AES baseline.",
            "Managed AES is shown as an informational reference only and is not used as the speed-up baseline.",
            "Managed AES is benchmarked only for CBC and GCM.",
            "Decrypt benchmarks reuse a shared pre-generated ciphertext per iteration to reduce peak memory usage and keep inputs identical across engines.",
            request.Algorithm == CryptoAlgorithm.Gcm ? "Padding is ignored for GCM." : "Padding may change the output size for block-based processing."
        };

        if (RuntimeInformation.ProcessArchitecture == Architecture.X86 && request.DataSizeMegabytes >= 64)
        {
            parts.Add("The benchmark is running in a 32-bit process, so large payloads may hit tighter memory limits, especially for decrypt benchmarks.");
        }

        return string.Join(" ", parts);
    }

    private static List<BenchmarkSummary> BuildSummaries(IReadOnlyList<BenchmarkResultRow> rows)
    {
        return rows
            .GroupBy(row => new { row.Engine, row.Direction })
            .Select(group =>
            {
                var successfulRows = group.Where(row => row.Succeeded).OrderBy(row => row.ElapsedMilliseconds).ToList();
                if (successfulRows.Count == 0)
                {
                    return new BenchmarkSummary
                    {
                        Engine = group.Key.Engine,
                        Direction = group.Key.Direction,
                        Samples = 0,
                        AverageMilliseconds = 0,
                        MedianMilliseconds = 0,
                        BestMilliseconds = 0,
                        AverageThroughputMegabytesPerSecond = 0,
                        BestThroughputMegabytesPerSecond = 0,
                        Succeeded = false,
                        Note = string.Join(" | ", group.Where(row => !string.IsNullOrWhiteSpace(row.Note)).Select(row => row.Note).Distinct())
                    };
                }

                var median = successfulRows.Count % 2 == 1
                    ? successfulRows[successfulRows.Count / 2].ElapsedMilliseconds
                    : (successfulRows[(successfulRows.Count / 2) - 1].ElapsedMilliseconds + successfulRows[successfulRows.Count / 2].ElapsedMilliseconds) / 2d;

                return new BenchmarkSummary
                {
                    Engine = group.Key.Engine,
                    Direction = group.Key.Direction,
                    Samples = successfulRows.Count,
                    AverageMilliseconds = successfulRows.Average(row => row.ElapsedMilliseconds),
                    MedianMilliseconds = median,
                    BestMilliseconds = successfulRows.Min(row => row.ElapsedMilliseconds),
                    AverageThroughputMegabytesPerSecond = successfulRows.Average(row => row.ThroughputMegabytesPerSecond),
                    BestThroughputMegabytesPerSecond = successfulRows.Max(row => row.ThroughputMegabytesPerSecond),
                    Succeeded = true
                };
            })
            .OrderBy(summary => summary.Direction)
            .ThenBy(summary => summary.Engine)
            .ToList();
    }

    private static void ApplyRelativeMetrics(List<BenchmarkResultRow> rows, List<BenchmarkSummary> summaries)
    {
        foreach (var direction in Enum.GetValues<BenchmarkDirection>())
        {
            var nativeCpuAverage = summaries.FirstOrDefault(summary => summary.Direction == direction && summary.Engine == CryptoEngine.NativeCpu && summary.Succeeded)?.AverageMilliseconds;

            foreach (var row in rows.Where(row => row.Direction == direction))
            {
                row.RelativeSpeedupVsManagedAes = null;
                row.RelativeSpeedupVsNativeCpu = row.Succeeded && row.Engine == CryptoEngine.OpenCl && nativeCpuAverage.HasValue && row.ElapsedMilliseconds > 0
                    ? nativeCpuAverage.Value / row.ElapsedMilliseconds
                    : null;
            }
        }

        for (var index = 0; index < summaries.Count; index++)
        {
            var summary = summaries[index];
            var nativeCpuAverage = summaries.FirstOrDefault(candidate => candidate.Direction == summary.Direction && candidate.Engine == CryptoEngine.NativeCpu && candidate.Succeeded)?.AverageMilliseconds;

            summaries[index] = new BenchmarkSummary
            {
                Engine = summary.Engine,
                Direction = summary.Direction,
                Samples = summary.Samples,
                AverageMilliseconds = summary.AverageMilliseconds,
                MedianMilliseconds = summary.MedianMilliseconds,
                BestMilliseconds = summary.BestMilliseconds,
                AverageThroughputMegabytesPerSecond = summary.AverageThroughputMegabytesPerSecond,
                BestThroughputMegabytesPerSecond = summary.BestThroughputMegabytesPerSecond,
                Succeeded = summary.Succeeded,
                Note = summary.Note,
                RelativeSpeedupVsNativeCpu = summary.Succeeded && summary.Engine == CryptoEngine.OpenCl && nativeCpuAverage.HasValue && summary.AverageMilliseconds > 0
                    ? nativeCpuAverage.Value / summary.AverageMilliseconds
                    : null,
                RelativeSpeedupVsManagedAes = null
            };
        }
    }
}
