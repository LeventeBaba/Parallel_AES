#include "crypto_ctr_stream.h"

#include <string.h>

static void secure_zero(void* p, size_t n)
{
    volatile uint8_t* v = (volatile uint8_t*)p;
    while (n--) {
        *v++ = 0;
    }
}

void crypto_ctr_stream_init(crypto_ctr_stream_state_t* state, uint64_t initial_block_offset)
{
    if (!state) {
        return;
    }

    memset(state, 0, sizeof(*state));
    state->next_block_offset = initial_block_offset;
    state->keystream_offset = 16;
}

crypto_status_t crypto_ctr_stream_xor(crypto_ctr_stream_state_t* state,
                                     crypto_ctr_stream_xor_fn xor_fn,
                                     void* context,
                                     const uint8_t* input,
                                     uint8_t* output,
                                     size_t len)
{
    static const uint8_t zeros[16] = { 0 };
    size_t offset = 0;
    crypto_status_t st;

    if (!state || !xor_fn || !input || !output) {
        return CRYPTO_INVALID_ARG;
    }

    if (len == 0) {
        return CRYPTO_OK;
    }

    if (state->keystream_offset < 16) {
        size_t remain = 16 - state->keystream_offset;
        size_t take = len < remain ? len : remain;

        for (size_t i = 0; i < take; i++) {
            output[i] = (uint8_t)(input[i] ^ state->keystream[state->keystream_offset + i]);
        }

        state->keystream_offset += take;
        offset += take;
    }

    if (state->keystream_offset == 16) {
        state->keystream_offset = 16;
    }

    if (offset < len) {
        size_t remaining = len - offset;
        size_t bulk_len = (remaining / 16) * 16;

        if (bulk_len) {
            st = xor_fn(context, input + offset, output + offset, bulk_len, state->next_block_offset);
            if (st != CRYPTO_OK) {
                return st;
            }

            state->next_block_offset += (uint64_t)(bulk_len / 16);
            offset += bulk_len;
        }
    }

    if (offset < len) {
        size_t tail_len = len - offset;

        st = xor_fn(context, zeros, state->keystream, 16, state->next_block_offset);
        if (st != CRYPTO_OK) {
            return st;
        }

        state->next_block_offset += 1u;

        for (size_t i = 0; i < tail_len; i++) {
            output[offset + i] = (uint8_t)(input[offset + i] ^ state->keystream[i]);
        }

        state->keystream_offset = tail_len;
    }

    return CRYPTO_OK;
}

void crypto_ctr_stream_clear(crypto_ctr_stream_state_t* state)
{
    if (!state) {
        return;
    }

    secure_zero(state, sizeof(*state));
}
