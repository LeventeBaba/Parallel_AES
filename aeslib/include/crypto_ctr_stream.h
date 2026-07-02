#ifndef CRYPTO_CTR_STREAM_H
#define CRYPTO_CTR_STREAM_H

#include <stddef.h>
#include <stdint.h>

#include "crypto_status.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef crypto_status_t (*crypto_ctr_stream_xor_fn)(void* context,
                                                   const uint8_t* input,
                                                   uint8_t* output,
                                                   size_t len,
                                                   uint64_t block_offset);

typedef struct crypto_ctr_stream_state_t {
    uint64_t next_block_offset;
    uint8_t keystream[16];
    size_t keystream_offset;
} crypto_ctr_stream_state_t;

void crypto_ctr_stream_init(crypto_ctr_stream_state_t* state, uint64_t initial_block_offset);

crypto_status_t crypto_ctr_stream_xor(crypto_ctr_stream_state_t* state,
                                     crypto_ctr_stream_xor_fn xor_fn,
                                     void* context,
                                     const uint8_t* input,
                                     uint8_t* output,
                                     size_t len);

void crypto_ctr_stream_clear(crypto_ctr_stream_state_t* state);

#ifdef __cplusplus
}
#endif

#endif
