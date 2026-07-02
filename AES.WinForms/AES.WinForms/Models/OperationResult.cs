namespace AES.WinForms.Models;

public sealed class OperationResult<T>
{
    public bool Succeeded { get; init; }
    public string Message { get; init; } = string.Empty;
    public T? Value { get; init; }

    public static OperationResult<T> Success(T value, string message = "") => new()
    {
        Succeeded = true,
        Value = value,
        Message = message
    };

    public static OperationResult<T> Failure(string message) => new()
    {
        Succeeded = false,
        Message = message
    };
}
