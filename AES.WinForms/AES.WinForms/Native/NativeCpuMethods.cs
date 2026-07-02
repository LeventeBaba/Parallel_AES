using System.Runtime.InteropServices;

namespace AES.WinForms.Native;

internal static class NativeCpuMethods
{
    private const string LibraryName = "crypto_aes.dll";

    [DllImport(LibraryName, EntryPoint = "crypto_ffi_aes_cbc_encrypt_alloc", CallingConvention = CallingConvention.Cdecl)]
    internal static extern NativeStatus AesCbcEncryptAlloc(byte[] key, nuint keyLenBytes, byte[] iv16, int padding, byte[] plaintext, nuint plaintextLen, out nint ciphertextOut, out nuint ciphertextLenOut);

    [DllImport(LibraryName, EntryPoint = "crypto_ffi_aes_cbc_decrypt_alloc", CallingConvention = CallingConvention.Cdecl)]
    internal static extern NativeStatus AesCbcDecryptAlloc(byte[] key, nuint keyLenBytes, byte[] iv16, int padding, byte[] ciphertext, nuint ciphertextLen, out nint plaintextOut, out nuint plaintextLenOut);

    

    [DllImport(LibraryName, EntryPoint = "crypto_ffi_aes_cbc_encrypt_file", CallingConvention = CallingConvention.Cdecl)]
    internal static extern NativeStatus AesCbcEncryptFile(byte[] key, nuint keyLenBytes, byte[] iv16, int padding, [MarshalAs(UnmanagedType.LPStr)] string inputPath, [MarshalAs(UnmanagedType.LPStr)] string outputPath, int prefixIv);

    [DllImport(LibraryName, EntryPoint = "crypto_ffi_aes_cbc_decrypt_file", CallingConvention = CallingConvention.Cdecl)]
    internal static extern NativeStatus AesCbcDecryptFile(byte[] key, nuint keyLenBytes, byte[] iv16, int padding, [MarshalAs(UnmanagedType.LPStr)] string inputPath, [MarshalAs(UnmanagedType.LPStr)] string outputPath, int prefixIv);

    [DllImport(LibraryName, EntryPoint = "crypto_ffi_aes_ctr_encrypt_alloc", CallingConvention = CallingConvention.Cdecl)]
    internal static extern NativeStatus AesCtrEncryptAlloc(byte[] key, nuint keyLenBytes, byte[] iv16, int padding, byte[] plaintext, nuint plaintextLen, out nint ciphertextOut, out nuint ciphertextLenOut);

    [DllImport(LibraryName, EntryPoint = "crypto_ffi_aes_ctr_decrypt_alloc", CallingConvention = CallingConvention.Cdecl)]
    internal static extern NativeStatus AesCtrDecryptAlloc(byte[] key, nuint keyLenBytes, byte[] iv16, int padding, byte[] ciphertext, nuint ciphertextLen, out nint plaintextOut, out nuint plaintextLenOut);

    

    [DllImport(LibraryName, EntryPoint = "crypto_ffi_aes_ctr_encrypt_file", CallingConvention = CallingConvention.Cdecl)]
    internal static extern NativeStatus AesCtrEncryptFile(byte[] key, nuint keyLenBytes, byte[] iv16, int padding, [MarshalAs(UnmanagedType.LPStr)] string inputPath, [MarshalAs(UnmanagedType.LPStr)] string outputPath, int prefixIv);

    [DllImport(LibraryName, EntryPoint = "crypto_ffi_aes_ctr_decrypt_file", CallingConvention = CallingConvention.Cdecl)]
    internal static extern NativeStatus AesCtrDecryptFile(byte[] key, nuint keyLenBytes, byte[] iv16, int padding, [MarshalAs(UnmanagedType.LPStr)] string inputPath, [MarshalAs(UnmanagedType.LPStr)] string outputPath, int prefixIv);

    [DllImport(LibraryName, EntryPoint = "crypto_ffi_aes_gcm_encrypt_alloc", CallingConvention = CallingConvention.Cdecl)]
    internal static extern NativeStatus AesGcmEncryptAlloc(byte[] key, nuint keyLenBytes, byte[] iv, nuint ivLen, byte[]? aad, nuint aadLen, byte[] plaintext, nuint plaintextLen, out nint ciphertextOut, out nuint ciphertextLenOut, byte[] tag16Out);

    [DllImport(LibraryName, EntryPoint = "crypto_ffi_aes_gcm_decrypt_alloc", CallingConvention = CallingConvention.Cdecl)]
    internal static extern NativeStatus AesGcmDecryptAlloc(byte[] key, nuint keyLenBytes, byte[] iv, nuint ivLen, byte[]? aad, nuint aadLen, byte[] ciphertext, nuint ciphertextLen, byte[] tag16, out nint plaintextOut, out nuint plaintextLenOut);

    [DllImport(LibraryName, EntryPoint = "crypto_ffi_aes_gcm_encrypt_file", CallingConvention = CallingConvention.Cdecl)]
    internal static extern NativeStatus AesGcmEncryptFile(byte[] key, nuint keyLenBytes, byte[] iv, nuint ivLen, byte[]? aad, nuint aadLen, [MarshalAs(UnmanagedType.LPStr)] string inputPath, [MarshalAs(UnmanagedType.LPStr)] string outputPath, byte[] tag16Out);

    [DllImport(LibraryName, EntryPoint = "crypto_ffi_aes_gcm_decrypt_file", CallingConvention = CallingConvention.Cdecl)]
    internal static extern NativeStatus AesGcmDecryptFile(byte[] key, nuint keyLenBytes, byte[] iv, nuint ivLen, byte[]? aad, nuint aadLen, [MarshalAs(UnmanagedType.LPStr)] string inputPath, [MarshalAs(UnmanagedType.LPStr)] string outputPath, byte[] tag16);

    [DllImport(LibraryName, EntryPoint = "crypto_ffi_free", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void Free(nint pointer);
}
