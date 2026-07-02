#ifndef CRYPTO_GCM_STREAM_H
#define CRYPTO_GCM_STREAM_H

#include <stddef.h>
#include <stdint.h>

#include "aes.h"
#include "crypto_status.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct crypto_gcm_stream_state_t {
    uint8_t h[16];
    uint8_t j0[16];
    uint8_t y[16];
    uint64_t aad_len;
    uint64_t ciphertext_len;
} crypto_gcm_stream_state_t;

crypto_status_t crypto_gcm_stream_init(crypto_gcm_stream_state_t* state,
                                      const crypto_aes_t* aes,
                                      const uint8_t* iv,
                                      size_t iv_len,
                                      const uint8_t* aad,
                                      size_t aad_len);

crypto_status_t crypto_gcm_stream_update_ciphertext(crypto_gcm_stream_state_t* state,
                                                   const uint8_t* ciphertext,
                                                   size_t ciphertext_len);

crypto_status_t crypto_gcm_stream_finalize_tag(const crypto_gcm_stream_state_t* state,
                                              const crypto_aes_t* aes,
                                              uint8_t tag16_out[16]);

void crypto_gcm_stream_clear(crypto_gcm_stream_state_t* state);

#ifdef __cplusplus
}
#endif

#endif
