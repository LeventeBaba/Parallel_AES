#include "aes_gcm.h"

#include <string.h>

#include "aes.h"
#include "crypto_gf128.h"

#ifdef CRYPTO_PROFILE
#include "crypto_profile.h"
#include "crypto_timer.h"
#endif

static void secure_zero(void* p, size_t n)
{
    volatile uint8_t* v = (volatile uint8_t*)p;
    while (n--) {
        *v++ = 0;
    }
}

static uint32_t be32_load(const uint8_t b[4])
{
    return ((uint32_t)b[0] << 24) |
           ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) |
           ((uint32_t)b[3]);
}

static void be32_store(uint32_t v, uint8_t out[4])
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)(v);
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

static int ct_mem_equal_16(const uint8_t a[16], const uint8_t b[16])
{
    uint8_t r = 0;
    for (int i = 0; i < 16; i++) {
        r |= (uint8_t)(a[i] ^ b[i]);
    }
    return r == 0;
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
        for (int i = 0; i < 16; i++) {
            last[i] = 0;
        }
        for (size_t i = 0; i < rem; i++) {
            last[i] = data[full + i];
        }
        ghash_update_block(h, y, last);
        secure_zero(last, sizeof(last));
    }
}

static void ghash_lengths(const uint8_t h[16], uint8_t y[16], uint64_t aad_len, uint64_t ct_len)
{
    uint8_t blk[16];
    be64_store(aad_len * 8u, blk);
    be64_store(ct_len * 8u, blk + 8);
    ghash_update_block(h, y, blk);
    secure_zero(blk, sizeof(blk));
}

static void gcm_compute_j0(const uint8_t h[16], const uint8_t* iv, size_t iv_len, uint8_t j0[16])
{
#ifdef CRYPTO_PROFILE
    uint64_t t0 = crypto_time_now_ns();
#endif
    if (iv_len == 12) {
        memcpy(j0, iv, 12);
        j0[12] = 0;
        j0[13] = 0;
        j0[14] = 0;
        j0[15] = 1;
#ifdef CRYPTO_PROFILE
        crypto_profile_add_aes_gcm_j0(crypto_time_now_ns() - t0);
#endif
        return;
    }

    for (int i = 0; i < 16; i++) {
        j0[i] = 0;
    }

    ghash_update_bytes(h, j0, iv, iv_len);
    ghash_lengths(h, j0, 0, (uint64_t)iv_len);
#ifdef CRYPTO_PROFILE
    crypto_profile_add_aes_gcm_j0(crypto_time_now_ns() - t0);
#endif
}

static void gcm_inc32(uint8_t ctr[16])
{
    uint32_t v = be32_load(ctr + 12);
    v += 1u;
    be32_store(v, ctr + 12);
}

static void gcm_ctr_xor(const crypto_aes_t* aes, const uint8_t j0[16], const uint8_t* input, uint8_t* output, size_t len)
{
#ifdef CRYPTO_PROFILE
    uint64_t t0 = crypto_time_now_ns();
#endif
    uint8_t ctr[16];
    uint8_t ks[16];
    size_t blocks = (len + 15) / 16;

    memcpy(ctr, j0, 16);

    for (size_t b = 0; b < blocks; b++) {
        size_t off = b * 16;
        size_t n = (len - off) >= 16 ? 16 : (len - off);

        gcm_inc32(ctr);
        crypto_aes_encrypt_block(aes, ctr, ks);

        for (size_t i = 0; i < n; i++) {
            output[off + i] = (uint8_t)(input[off + i] ^ ks[i]);
        }
    }

    secure_zero(ctr, sizeof(ctr));
    secure_zero(ks, sizeof(ks));
#ifdef CRYPTO_PROFILE
    crypto_profile_add_aes_gcm_ctr(crypto_time_now_ns() - t0);
#endif
}

static void gcm_auth_tag(const crypto_aes_t* aes,
                         const uint8_t h[16],
                         const uint8_t* iv,
                         size_t iv_len,
                         const uint8_t* aad,
                         size_t aad_len,
                         const uint8_t* ciphertext,
                         size_t ciphertext_len,
                         uint8_t tag16_out[16])
{
#ifdef CRYPTO_PROFILE
    uint64_t t0 = crypto_time_now_ns();
    uint64_t tf = 0;
#endif
    uint8_t j0[16];
    uint8_t y[16];
    uint8_t s[16];

    gcm_compute_j0(h, iv, iv_len, j0);

    for (int i = 0; i < 16; i++) {
        y[i] = 0;
    }

    if (aad && aad_len) {
        ghash_update_bytes(h, y, aad, aad_len);
    }

    if (ciphertext && ciphertext_len) {
        ghash_update_bytes(h, y, ciphertext, ciphertext_len);
    }

    ghash_lengths(h, y, (uint64_t)aad_len, (uint64_t)ciphertext_len);

#ifdef CRYPTO_PROFILE
    tf = crypto_time_now_ns();
#endif
    crypto_aes_encrypt_block(aes, j0, s);
    crypto_gf128_xor(tag16_out, y, s);
#ifdef CRYPTO_PROFILE
    crypto_profile_add_aes_gcm_auth_finalize(crypto_time_now_ns() - tf);
#endif

    secure_zero(j0, sizeof(j0));
    secure_zero(y, sizeof(y));
    secure_zero(s, sizeof(s));
#ifdef CRYPTO_PROFILE
    crypto_profile_add_aes_gcm_auth(crypto_time_now_ns() - t0);
#endif
}

crypto_status_t crypto_aes_gcm_encrypt(const uint8_t* key,
                                      size_t key_len_bytes,
                                      const uint8_t* iv,
                                      size_t iv_len,
                                      const uint8_t* aad,
                                      size_t aad_len,
                                      const uint8_t* plaintext,
                                      size_t plaintext_len,
                                      uint8_t* ciphertext,
                                      uint8_t tag16_out[16])
{
#ifdef CRYPTO_PROFILE
    uint64_t t0 = crypto_time_now_ns();
#endif
    crypto_aes_t aes;
    crypto_status_t st;
    uint8_t h[16];
    uint8_t j0[16];

    if (!key || !iv || !ciphertext || !tag16_out) {
        return CRYPTO_INVALID_ARG;
    }

    if (plaintext_len && !plaintext) {
        return CRYPTO_INVALID_ARG;
    }

    if (aad_len && !aad) {
        return CRYPTO_INVALID_ARG;
    }

    st = crypto_aes_init(&aes, key, key_len_bytes);
    if (st != CRYPTO_OK) {
        return st;
    }

    memset(h, 0, sizeof(h));
    crypto_aes_encrypt_block(&aes, h, h);

    gcm_compute_j0(h, iv, iv_len, j0);

    if (plaintext_len) {
        gcm_ctr_xor(&aes, j0, plaintext, ciphertext, plaintext_len);
    }

    gcm_auth_tag(&aes, h, iv, iv_len, aad, aad_len, ciphertext, plaintext_len, tag16_out);

    crypto_aes_clear(&aes);
    secure_zero(h, sizeof(h));
    secure_zero(j0, sizeof(j0));
#ifdef CRYPTO_PROFILE
    crypto_profile_add_aes_gcm_encrypt(crypto_time_now_ns() - t0, plaintext_len);
#endif
    return CRYPTO_OK;
}

crypto_status_t crypto_aes_gcm_decrypt(const uint8_t* key,
                                      size_t key_len_bytes,
                                      const uint8_t* iv,
                                      size_t iv_len,
                                      const uint8_t* aad,
                                      size_t aad_len,
                                      const uint8_t* ciphertext,
                                      size_t ciphertext_len,
                                      const uint8_t tag16[16],
                                      uint8_t* plaintext_out)
{
#ifdef CRYPTO_PROFILE
    uint64_t t0 = crypto_time_now_ns();
#endif
    crypto_aes_t aes;
    crypto_status_t st;
    uint8_t h[16];
    uint8_t expected[16];
    uint8_t j0[16];

    if (!key || !iv || !ciphertext || !tag16 || !plaintext_out) {
        return CRYPTO_INVALID_ARG;
    }

    if (aad_len && !aad) {
        return CRYPTO_INVALID_ARG;
    }

    st = crypto_aes_init(&aes, key, key_len_bytes);
    if (st != CRYPTO_OK) {
        return st;
    }

    memset(h, 0, sizeof(h));
    crypto_aes_encrypt_block(&aes, h, h);

    gcm_auth_tag(&aes, h, iv, iv_len, aad, aad_len, ciphertext, ciphertext_len, expected);

    if (!ct_mem_equal_16(expected, tag16)) {
        crypto_aes_clear(&aes);
        secure_zero(h, sizeof(h));
        secure_zero(expected, sizeof(expected));
        return CRYPTO_AUTH_FAILED;
    }

    gcm_compute_j0(h, iv, iv_len, j0);

    if (ciphertext_len) {
        gcm_ctr_xor(&aes, j0, ciphertext, plaintext_out, ciphertext_len);
    }

    crypto_aes_clear(&aes);
    secure_zero(h, sizeof(h));
    secure_zero(expected, sizeof(expected));
    secure_zero(j0, sizeof(j0));
#ifdef CRYPTO_PROFILE
    crypto_profile_add_aes_gcm_decrypt(crypto_time_now_ns() - t0, ciphertext_len);
#endif
    return CRYPTO_OK;
}
