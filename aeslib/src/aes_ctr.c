#include "aes_ctr.h"

#ifdef CRYPTO_PROFILE
#include "crypto_profile.h"
#include "crypto_timer.h"
#endif

static uint64_t be64_load(const uint8_t b[8])
{
    return ((uint64_t)b[0] << 56) |
           ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) |
           ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) |
           ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8) |
           ((uint64_t)b[7]);
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

static void u128_add_u64(uint64_t hi_in, uint64_t lo_in, uint64_t add, uint64_t* hi_out, uint64_t* lo_out)
{
    uint64_t lo = lo_in + add;
    uint64_t carry = (lo < lo_in) ? 1u : 0u;
    uint64_t hi = hi_in + carry;
    *hi_out = hi;
    *lo_out = lo;
}

crypto_status_t crypto_aes_ctr_xor_aes(const crypto_aes_t* aes,
                                      const uint8_t iv16[16],
                                      const uint8_t* input,
                                      uint8_t* output,
                                      size_t len,
                                      uint64_t block_offset)
{
#ifdef CRYPTO_PROFILE
    uint64_t t0 = crypto_time_now_ns();
    uint64_t counter_ns = 0;
    uint64_t xor_ns = 0;
#endif
    uint64_t iv_hi;
    uint64_t iv_lo;
    size_t blocks;

    if (!aes || !iv16 || !input || !output) {
        return CRYPTO_INVALID_ARG;
    }

    if (len == 0) {
        return CRYPTO_OK;
    }

    iv_hi = be64_load(iv16);
    iv_lo = be64_load(iv16 + 8);

    blocks = (len + 15) / 16;
    for (size_t b = 0; b < blocks; b++) {
        uint64_t c_hi;
        uint64_t c_lo;
        uint8_t counter[16];
        uint8_t ks[16];
        size_t off = b * 16;
        size_t n = (len - off) >= 16 ? 16 : (len - off);

#ifdef CRYPTO_PROFILE
        {
            uint64_t tc = crypto_time_now_ns();
            u128_add_u64(iv_hi, iv_lo, block_offset + (uint64_t)b, &c_hi, &c_lo);
            be64_store(c_hi, counter);
            be64_store(c_lo, counter + 8);
            counter_ns += crypto_time_now_ns() - tc;
        }
#else
        u128_add_u64(iv_hi, iv_lo, block_offset + (uint64_t)b, &c_hi, &c_lo);
        be64_store(c_hi, counter);
        be64_store(c_lo, counter + 8);
#endif

        crypto_aes_encrypt_block(aes, counter, ks);

#ifdef CRYPTO_PROFILE
        {
            uint64_t tx = crypto_time_now_ns();
            for (size_t i = 0; i < n; i++) {
                output[off + i] = (uint8_t)(input[off + i] ^ ks[i]);
            }
            xor_ns += crypto_time_now_ns() - tx;
        }
#else
        for (size_t i = 0; i < n; i++) {
            output[off + i] = (uint8_t)(input[off + i] ^ ks[i]);
        }
#endif
    }

#ifdef CRYPTO_PROFILE
    crypto_profile_add_aes_ctr(crypto_time_now_ns() - t0, len, counter_ns, xor_ns);
#endif
    return CRYPTO_OK;
}

crypto_status_t crypto_aes_ctr_xor(const uint8_t* key,
                                  size_t key_len_bytes,
                                  const uint8_t iv16[16],
                                  const uint8_t* input,
                                  uint8_t* output,
                                  size_t len,
                                  uint64_t block_offset)
{
    crypto_aes_t aes;
    crypto_status_t st;

    if (!key || !iv16 || !input || !output) {
        return CRYPTO_INVALID_ARG;
    }

    if (len == 0) {
        return CRYPTO_OK;
    }

    st = crypto_aes_init(&aes, key, key_len_bytes);
    if (st != CRYPTO_OK) {
        crypto_aes_clear(&aes);
        return st;
    }

    st = crypto_aes_ctr_xor_aes(&aes, iv16, input, output, len, block_offset);
    crypto_aes_clear(&aes);
    return st;
}
