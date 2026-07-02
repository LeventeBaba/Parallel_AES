#include "crypto_gcm_stream.h"

#include <string.h>

#include "crypto_gf128.h"

static void secure_zero(void* p, size_t n)
{
    volatile uint8_t* v = (volatile uint8_t*)p;
    while (n--) {
        *v++ = 0;
    }
}

static void be64_store(uint64_t v, uint8_t out[8])
{
    out[0] = (uint8_t)(v >> 56);
    out[1] = (uint8_t)(v >> 48);
    out[2] = (uint8_t)(v >> 40);
    out[3] = (uint8_t)(v >> 32);
    out[4] = (uint8_t)(v >> 24);
    out[5] = (uint8_t)(v >> 16);
    out[6] = (uint8_t)(v >> 8);
    out[7] = (uint8_t)(v);
}

static void ghash_update_block(const uint8_t h[16], uint8_t y[16], const uint8_t x[16])
{
    uint8_t t[16];
    crypto_gf128_xor(t, y, x);
    crypto_gf128_mul(t, h, y);
    secure_zero(t, sizeof(t));
}

static void ghash_update_bytes(const uint8_t h[16], uint8_t y[16], const uint8_t* data, size_t data_len)
{
    size_t full = (data_len / 16) * 16;
    size_t rem = data_len - full;

    for (size_t off = 0; off < full; off += 16) {
        ghash_update_block(h, y, data + off);
    }

    if (rem) {
        uint8_t last[16];
        memset(last, 0, sizeof(last));
        memcpy(last, data + full, rem);
        ghash_update_block(h, y, last);
        secure_zero(last, sizeof(last));
    }
}

static void ghash_lengths(const uint8_t h[16], uint8_t y[16], uint64_t aad_len, uint64_t ciphertext_len)
{
    uint8_t blk[16];
    be64_store(aad_len * 8u, blk);
    be64_store(ciphertext_len * 8u, blk + 8);
    ghash_update_block(h, y, blk);
    secure_zero(blk, sizeof(blk));
}

static void gcm_compute_j0(const uint8_t h[16], const uint8_t* iv, size_t iv_len, uint8_t j0[16])
{
    if (iv_len == 12) {
        memcpy(j0, iv, 12);
        j0[12] = 0;
        j0[13] = 0;
        j0[14] = 0;
        j0[15] = 1;
        return;
    }

    memset(j0, 0, 16);
    ghash_update_bytes(h, j0, iv, iv_len);
    ghash_lengths(h, j0, 0, (uint64_t)iv_len);
}

crypto_status_t crypto_gcm_stream_init(crypto_gcm_stream_state_t* state,
                                      const crypto_aes_t* aes,
                                      const uint8_t* iv,
                                      size_t iv_len,
                                      const uint8_t* aad,
                                      size_t aad_len)
{
    if (!state || !aes || !iv) {
        return CRYPTO_INVALID_ARG;
    }

    if (aad_len && !aad) {
        return CRYPTO_INVALID_ARG;
    }

    memset(state, 0, sizeof(*state));
    crypto_aes_encrypt_block(aes, state->h, state->h);
    gcm_compute_j0(state->h, iv, iv_len, state->j0);
    state->aad_len = (uint64_t)aad_len;

    if (aad_len) {
        ghash_update_bytes(state->h, state->y, aad, aad_len);
    }

    return CRYPTO_OK;
}

crypto_status_t crypto_gcm_stream_update_ciphertext(crypto_gcm_stream_state_t* state,
                                                   const uint8_t* ciphertext,
                                                   size_t ciphertext_len)
{
    if (!state) {
        return CRYPTO_INVALID_ARG;
    }

    if (ciphertext_len && !ciphertext) {
        return CRYPTO_INVALID_ARG;
    }

    if (ciphertext_len) {
        ghash_update_bytes(state->h, state->y, ciphertext, ciphertext_len);
        state->ciphertext_len += (uint64_t)ciphertext_len;
    }

    return CRYPTO_OK;
}

crypto_status_t crypto_gcm_stream_finalize_tag(const crypto_gcm_stream_state_t* state,
                                              const crypto_aes_t* aes,
                                              uint8_t tag16_out[16])
{
    uint8_t y[16];
    uint8_t s[16];

    if (!state || !aes || !tag16_out) {
        return CRYPTO_INVALID_ARG;
    }

    memcpy(y, state->y, sizeof(y));
    ghash_lengths(state->h, y, state->aad_len, state->ciphertext_len);
    crypto_aes_encrypt_block(aes, state->j0, s);
    crypto_gf128_xor(tag16_out, y, s);
    secure_zero(y, sizeof(y));
    secure_zero(s, sizeof(s));
    return CRYPTO_OK;
}

void crypto_gcm_stream_clear(crypto_gcm_stream_state_t* state)
{
    if (!state) {
        return;
    }

    secure_zero(state, sizeof(*state));
}
