namespace AES.WinForms.Models;

public sealed class BenchmarkSession
{
    public required Guid SessionId { get; init; }
    public required DateTimeOffset CreatedUtc { get; init; }
    public required BenchmarkRequest Request { get; init; }
    public required string SaltBase64 { get; init; }
    public required string Iv16Base64 { get; init; }
    public required string Iv12Base64 { get; init; }
    public required string AadBase64 { get; init; }
    public required IReadOnlyList<BenchmarkResultRow> Rows { get; init; }
    public required IReadOnlyList<BenchmarkSummary> Summaries { get; init; }
    public required BenchmarkEnvironmentInfo EnvironmentInfo { get; init; }
    public required string EnvironmentDescription { get; init; }
    public string Notes { get; init; } = string.Empty;
}
