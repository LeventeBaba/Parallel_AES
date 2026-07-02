#ifndef OPENCL_AES_GCM_H
#define OPENCL_AES_GCM_H

#include <stddef.h>
#include <stdint.h>

#include "crypto_status.h"

#ifdef __cplusplus
extern "C" {
#endif

crypto_status_t crypto_ocl_aes_gcm_ctr_xor_round_keys(const uint8_t* round_keys,
                                                           size_t round_keys_len,
                                                           const uint8_t j0[16],
                                                           const uint8_t* input,
                                                           uint8_t* output,
                                                           size_t len,
                                                           uint64_t block_offset,
                                                           uint64_t* out_kernel_ns);

crypto_status_t crypto_ocl_aes_gcm_encrypt(const uint8_t* key,
                                          size_t key_len_bytes,
                                          const uint8_t* iv,
                                          size_t iv_len,
                                          const uint8_t* aad,
                                          size_t aad_len,
                                          const uint8_t* plaintext,
                                          size_t plaintext_len,
                                          uint8_t* ciphertext_out,
                                          uint8_t tag16_out[16],
                                          uint64_t* out_kernel_ns);

crypto_status_t crypto_ocl_aes_gcm_decrypt(const uint8_t* key,
                                          size_t key_len_bytes,
                                          const uint8_t* iv,
                                          size_t iv_len,
                                          const uint8_t* aad,
                                          size_t aad_len,
                                          const uint8_t* ciphertext,
                                          size_t ciphertext_len,
                                          const uint8_t tag16[16],
                                          uint8_t* plaintext_out,
                                          uint64_t* out_kernel_ns);

#ifdef __cplusplus
}
#endif

#endif
