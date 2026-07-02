#ifndef AES_GCM_H
#define AES_GCM_H

#include <stddef.h>
#include <stdint.h>

#include "crypto_status.h"

#ifdef __cplusplus
extern "C" {
#endif

crypto_status_t crypto_aes_gcm_encrypt(const uint8_t* key,
                                      size_t key_len_bytes,
                                      const uint8_t* iv,
                                      size_t iv_len,
                                      const uint8_t* aad,
                                      size_t aad_len,
                                      const uint8_t* plaintext,
                                      size_t plaintext_len,
                                      uint8_t* ciphertext,
                                      uint8_t tag16_out[16]);

crypto_status_t crypto_aes_gcm_decrypt(const uint8_t* key,
                                      size_t key_len_bytes,
                                      const uint8_t* iv,
                                      size_t iv_len,
                                      const uint8_t* aad,
                                      size_t aad_len,
                                      const uint8_t* ciphertext,
                                      size_t ciphertext_len,
                                      const uint8_t tag16[16],
                                      uint8_t* plaintext_out);

#ifdef __cplusplus
}
#endif

#endif
