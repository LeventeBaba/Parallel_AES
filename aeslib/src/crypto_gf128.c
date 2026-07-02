#include "crypto_gf128.h"

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

void crypto_gf128_xor(uint8_t out[16], const uint8_t a[16], const uint8_t b[16])
{
    for (int i = 0; i < 16; i++) {
        out[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

static void gf128_shift_right(uint64_t* hi, uint64_t* lo)
{
    uint64_t l = *lo;
    uint64_t h = *hi;
    *lo = (l >> 1) | (h << 63);
    *hi = (h >> 1);
}

void crypto_gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t out[16])
{
#ifdef CRYPTO_PROFILE
    uint64_t t0 = crypto_time_now_ns();
#endif
    uint64_t z_hi = 0;
    uint64_t z_lo = 0;

    uint64_t v_hi = be64_load(y);
    uint64_t v_lo = be64_load(y + 8);

    for (int byte = 0; byte < 16; byte++) {
        uint8_t xb = x[byte];
        for (int bit = 7; bit >= 0; bit--) {
            uint64_t lsb = v_lo & 1u;
            uint64_t mask = (uint64_t)0 - (uint64_t)((xb >> bit) & 1u);

            z_hi ^= v_hi & mask;
            z_lo ^= v_lo & mask;

            gf128_shift_right(&v_hi, &v_lo);
            if (lsb) {
                v_hi ^= 0xe100000000000000ULL;
            }
        }
    }

    be64_store(z_hi, out);
    be64_store(z_lo, out + 8);
#ifdef CRYPTO_PROFILE
    crypto_profile_add_gf128_mul(crypto_time_now_ns() - t0);
#endif
}

static void gf128_set_one(uint8_t out[16])
{
    for (int i = 0; i < 16; i++) {
        out[i] = 0;
    }
    out[0] = 0x80;
}

void crypto_gf128_pow(const uint8_t h[16], uint64_t exponent, uint8_t out[16])
{
#ifdef CRYPTO_PROFILE
    uint64_t t0 = crypto_time_now_ns();
#endif
    uint8_t result[16];
    uint8_t base[16];
    uint8_t tmp[16];

    gf128_set_one(result);
    for (int i = 0; i < 16; i++) {
        base[i] = h[i];
    }

    while (exponent) {
        if (exponent & 1u) {
            crypto_gf128_mul(result, base, tmp);
            for (int i = 0; i < 16; i++) {
                result[i] = tmp[i];
            }
        }
        exponent >>= 1u;
        if (exponent) {
            crypto_gf128_mul(base, base, tmp);
            for (int i = 0; i < 16; i++) {
                base[i] = tmp[i];
            }
        }
    }

    for (int i = 0; i < 16; i++) {
        out[i] = result[i];
    }
#ifdef CRYPTO_PROFILE
    crypto_profile_add_gf128_pow(crypto_time_now_ns() - t0);
#endif
}
