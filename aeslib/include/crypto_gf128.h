#ifndef CRYPTO_GF128_H
#define CRYPTO_GF128_H

#include <stddef.h>
#include <stdint.h>

#include "crypto_status.h"

#ifdef __cplusplus
extern "C" {
#endif

void crypto_gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t out[16]);
void crypto_gf128_pow(const uint8_t h[16], uint64_t exponent, uint8_t out[16]);
void crypto_gf128_xor(uint8_t out[16], const uint8_t a[16], const uint8_t b[16]);

#ifdef __cplusplus
}
#endif

#endif
