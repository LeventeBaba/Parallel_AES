#ifndef CRYPTO_FFI_H
#define CRYPTO_FFI_H

#include <stddef.h>
#include <stdint.h>

#include "crypto_status.h"
#include "cbc.h"
#include "aes_gcm.h"

#ifdef __cplusplus
extern "C" {
#endif

crypto_status_t crypto_ffi_aes_cbc_encrypt_alloc(const uint8_t* key,
                                                size_t key_len_bytes,
                                                const uint8_t iv16[16],
                                                crypto_padding_t padding,
                                                const uint8_t* plaintext,
                                                size_t plaintext_len,
                                                uint8_t** ciphertext_out,
                                                size_t* ciphertext_len_out);

crypto_status_t crypto_ffi_aes_cbc_decrypt_alloc(const uint8_t* key,
                                                size_t key_len_bytes,
                                                const uint8_t iv16[16],
                                                crypto_padding_t padding,
                                                const uint8_t* ciphertext,
                                                size_t ciphertext_len,
                                                uint8_t** plaintext_out,
                                                size_t* plaintext_len_out);

crypto_status_t crypto_ffi_aes_cbc_encrypt_file(const uint8_t* key,
                                               size_t key_len_bytes,
                                               const uint8_t iv16[16],
                                               crypto_padding_t padding,
                                               const char* input_path,
                                               const char* output_path,
                                               int prefix_iv);

crypto_status_t crypto_ffi_aes_cbc_decrypt_file(const uint8_t* key,
                                               size_t key_len_bytes,
                                               const uint8_t iv16[16],
                                               crypto_padding_t padding,
                                               const char* input_path,
                                               const char* output_path,
                                               int prefix_iv);

crypto_status_t crypto_ffi_aes_ctr_encrypt_alloc(const uint8_t* key,
                                                size_t key_len_bytes,
                                                const uint8_t iv16[16],
                                                crypto_padding_t padding,
                                                const uint8_t* plaintext,
                                                size_t plaintext_len,
                                                uint8_t** ciphertext_out,
                                                size_t* ciphertext_len_out);

crypto_status_t crypto_ffi_aes_ctr_decrypt_alloc(const uint8_t* key,
                                                size_t key_len_bytes,
                                                const uint8_t iv16[16],
                                                crypto_padding_t padding,
                                                const uint8_t* ciphertext,
                                                size_t ciphertext_len,
                                                uint8_t** plaintext_out,
                                                size_t* plaintext_len_out);

crypto_status_t crypto_ffi_aes_ctr_encrypt_file(const uint8_t* key,
                                               size_t key_len_bytes,
                                               const uint8_t iv16[16],
                                               crypto_padding_t padding,
                                               const char* input_path,
                                               const char* output_path,
                                               int prefix_iv);

crypto_status_t crypto_ffi_aes_ctr_decrypt_file(const uint8_t* key,
                                               size_t key_len_bytes,
                                               const uint8_t iv16[16],
                                               crypto_padding_t padding,
                                               const char* input_path,
                                               const char* output_path,
                                               int prefix_iv);

crypto_status_t crypto_ffi_aes_gcm_encrypt_alloc(const uint8_t* key,
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

crypto_status_t crypto_ffi_aes_gcm_decrypt_alloc(const uint8_t* key,
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

crypto_status_t crypto_ffi_aes_gcm_encrypt_file(const uint8_t* key,
                                               size_t key_len_bytes,
                                               const uint8_t* iv,
                                               size_t iv_len,
                                               const uint8_t* aad,
                                               size_t aad_len,
                                               const char* input_path,
                                               const char* output_path,
                                               uint8_t tag16_out[16]);

crypto_status_t crypto_ffi_aes_gcm_decrypt_file(const uint8_t* key,
                                               size_t key_len_bytes,
                                               const uint8_t* iv,
                                               size_t iv_len,
                                               const uint8_t* aad,
                                               size_t aad_len,
                                               const char* input_path,
                                               const char* output_path,
                                               const uint8_t tag16[16]);

void crypto_ffi_free(void* p);

#ifdef __cplusplus
}
#endif

#endif
