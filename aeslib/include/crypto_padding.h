#ifndef CRYPTO_PADDING_H
#define CRYPTO_PADDING_H

#include <stddef.h>
#include <stdint.h>

#include "crypto_status.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum crypto_padding_t {
    CRYPTO_PADDING_PKCS7 = 1,
    CRYPTO_PADDING_ANSIX923 = 2,
    CRYPTO_PADDING_ISO7816_4 = 3,
    CRYPTO_PADDING_ZERO = 4,
    CRYPTO_PADDING_NONE = 5
} crypto_padding_t;

int crypto_padding_supported(crypto_padding_t padding);
crypto_status_t crypto_padding_padded_size(size_t n, crypto_padding_t padding, size_t* out_padded_size);
void crypto_padding_apply_block(uint8_t block[16], const uint8_t* tail, size_t tail_len, crypto_padding_t padding);
crypto_status_t crypto_padding_remove(const uint8_t* buf, size_t buf_len, crypto_padding_t padding, size_t* out_len);

#ifdef __cplusplus
}
#endif

#endif
