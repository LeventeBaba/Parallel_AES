#ifndef CRYPTO_AES_CTR_H
#define CRYPTO_AES_CTR_H

#include <stddef.h>
#include <stdint.h>

#include "aes.h"
#include "crypto_status.h"

#ifdef __cplusplus
extern "C" {
#endif

crypto_status_t crypto_aes_ctr_xor_aes(const crypto_aes_t* aes,
                                      const uint8_t iv16[16],
                                      const uint8_t* input,
                                      uint8_t* output,
                                      size_t len,
                                      uint64_t block_offset);

crypto_status_t crypto_aes_ctr_xor(const uint8_t* key,
                                  size_t key_len_bytes,
                                  const uint8_t iv16[16],
                                  const uint8_t* input,
                                  uint8_t* output,
                                  size_t len,
                                  uint64_t block_offset);

#ifdef __cplusplus
}
#endif

#endif
