namespace AES.WinForms.Native;

public enum NativeStatus
{
    Ok = 0,
    InvalidArg = -1,
    BufferTooSmall = -2,
    BadPadding = -3,
    IoError = -4,
    Unsupported = -5,
    InternalError = -6,
    AuthFailed = -7
}
