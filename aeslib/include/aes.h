#ifndef CRYPTO_AES_H
#define CRYPTO_AES_H

#include <stddef.h>
#include <stdint.h>

#include "crypto_status.h"
#include "crypto_block_cipher.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct crypto_aes_t {
    uint8_t round_keys[240];
    uint8_t rounds;
    uint8_t key_len;
} crypto_aes_t;

crypto_status_t crypto_aes_init(crypto_aes_t* aes, const uint8_t* key, size_t key_len_bytes);

static inline crypto_status_t crypto_aes128_init(crypto_aes_t* aes, const uint8_t key16[16])
{
    return crypto_aes_init(aes, key16, 16);
}

static inline crypto_status_t crypto_aes192_init(crypto_aes_t* aes, const uint8_t key24[24])
{
    return crypto_aes_init(aes, key24, 24);
}

static inline crypto_status_t crypto_aes256_init(crypto_aes_t* aes, const uint8_t key32[32])
{
    return crypto_aes_init(aes, key32, 32);
}

void crypto_aes_encrypt_block(const crypto_aes_t* aes, const uint8_t in_block[16], uint8_t out_block[16]);
void crypto_aes_decrypt_block(const crypto_aes_t* aes, const uint8_t in_block[16], uint8_t out_block[16]);

void crypto_aes_clear(crypto_aes_t* aes);

static inline int crypto_aes_rounds(const crypto_aes_t* aes)
{
    return aes ? (int)aes->rounds : 0;
}

static inline size_t crypto_aes_round_keys_bytes(const crypto_aes_t* aes)
{
    if (!aes) {
        return 0;
    }
    return (size_t)(aes->rounds + 1u) * 16u;
}

static inline const uint8_t* crypto_aes_round_keys_ptr(const crypto_aes_t* aes)
{
    return aes ? aes->round_keys : NULL;
}

crypto_block_cipher_t crypto_aes_block_cipher(const crypto_aes_t* aes);

#ifdef __cplusplus
}
#endif

#endif
