#ifndef CRYPTO_FFI_OPENCL_H
#define CRYPTO_FFI_OPENCL_H

#include <stddef.h>
#include <stdint.h>

#include "crypto_status.h"
#include "crypto_padding.h"

#ifdef _WIN32
  #ifdef CRYPTO_OPENCL_BUILD_DLL
    #define CRYPTO_OPENCL_API __declspec(dllexport)
  #else
    #define CRYPTO_OPENCL_API __declspec(dllimport)
  #endif
#else
  #define CRYPTO_OPENCL_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

CRYPTO_OPENCL_API crypto_status_t crypto_ffi_opencl_warmup(void);
CRYPTO_OPENCL_API void crypto_ffi_opencl_shutdown(void);
CRYPTO_OPENCL_API const char* crypto_ffi_opencl_last_error_message(void);
CRYPTO_OPENCL_API const char* crypto_ffi_opencl_platform_name(void);
CRYPTO_OPENCL_API const char* crypto_ffi_opencl_platform_version(void);
CRYPTO_OPENCL_API const char* crypto_ffi_opencl_device_name(void);
CRYPTO_OPENCL_API const char* crypto_ffi_opencl_device_version(void);
CRYPTO_OPENCL_API const char* crypto_ffi_opencl_device_opencl_c_version(void);

CRYPTO_OPENCL_API crypto_status_t crypto_ffi_opencl_aes_ctr_encrypt_alloc(const uint8_t* key,
                                                                          size_t key_len_bytes,
                                                                          const uint8_t iv16[16],
                                                                          crypto_padding_t padding,
                                                                          const uint8_t* plaintext,
                                                                          size_t plaintext_len,
                                                                          uint8_t** ciphertext_out,
                                                                          size_t* ciphertext_len_out);

CRYPTO_OPENCL_API crypto_status_t crypto_ffi_opencl_aes_ctr_decrypt_alloc(const uint8_t* key,
                                                                          size_t key_len_bytes,
                                                                          const uint8_t iv16[16],
                                                                          crypto_padding_t padding,
                                                                          const uint8_t* ciphertext,
                                                                          size_t ciphertext_len,
                                                                          uint8_t** plaintext_out,
                                                                          size_t* plaintext_len_out);

CRYPTO_OPENCL_API crypto_status_t crypto_ffi_opencl_aes_ctr_encrypt_file(const uint8_t* key,
                                                                         size_t key_len_bytes,
                                                                         const uint8_t iv16[16],
                                                                         crypto_padding_t padding,
                                                                         const char* input_path,
                                                                         const char* output_path,
                                                                         int prefix_iv);

CRYPTO_OPENCL_API crypto_status_t crypto_ffi_opencl_aes_ctr_decrypt_file(const uint8_t* key,
                                                                         size_t key_len_bytes,
                                                                         const uint8_t iv16[16],
                                                                         crypto_padding_t padding,
                                                                         const char* input_path,
                                                                         const char* output_path,
                                                                         int prefix_iv);

CRYPTO_OPENCL_API crypto_status_t crypto_ffi_opencl_aes_gcm_encrypt_alloc(const uint8_t* key,
                                                                          size_t key_len_bytes,
                                                                          const uint8_t* iv,
                                                                          size_t iv_len,
                                                                          const uint8_t* aad,
                                                                          size_t aad_len,
                                                                          const uint8_t* plaintext,
                                                                          size_t plaintext_len,
                                                                          uint8_t** ciphertext_out,
                                                                          size_t* ciphertext_len_out,
                                                                          uint8_t tag16_out[16]);

CRYPTO_OPENCL_API crypto_status_t crypto_ffi_opencl_aes_gcm_decrypt_alloc(const uint8_t* key,
                                                                          size_t key_len_bytes,
                                                                          const uint8_t* iv,
                                                                          size_t iv_len,
                                                                          const uint8_t* aad,
                                                                          size_t aad_len,
                                                                          const uint8_t* ciphertext,
                                                                          size_t ciphertext_len,
                                                                          const uint8_t tag16[16],
                                                                          uint8_t** plaintext_out,
                                                                          size_t* plaintext_len_out);

CRYPTO_OPENCL_API crypto_status_t crypto_ffi_opencl_aes_gcm_encrypt_file(const uint8_t* key,
                                                                         size_t key_len_bytes,
                                                                         const uint8_t* iv,
                                                                         size_t iv_len,
                                                                         const uint8_t* aad,
                                                                         size_t aad_len,
                                                                         const char* input_path,
                                                                         const char* output_path,
                                                                         uint8_t tag16_out[16]);

CRYPTO_OPENCL_API crypto_status_t crypto_ffi_opencl_aes_gcm_decrypt_file(const uint8_t* key,
                                                                         size_t key_len_bytes,
                                                                         const uint8_t* iv,
                                                                         size_t iv_len,
                                                                         const uint8_t* aad,
                                                                         size_t aad_len,
                                                                         const char* input_path,
                                                                         const char* output_path,
                                                                         const uint8_t tag16[16]);

CRYPTO_OPENCL_API void crypto_ffi_opencl_free(void* p);

#ifdef __cplusplus
}
#endif

#endif
