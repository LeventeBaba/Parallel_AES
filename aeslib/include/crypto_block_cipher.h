#ifndef CRYPTO_BLOCK_CIPHER_H
#define CRYPTO_BLOCK_CIPHER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct crypto_block_cipher_vtable_t {
    size_t block_size;
    void (*encrypt_block)(const void* ctx, const uint8_t* in_block, uint8_t* out_block);
    void (*decrypt_block)(const void* ctx, const uint8_t* in_block, uint8_t* out_block);
    void (*clear)(void* ctx);
} crypto_block_cipher_vtable_t;

typedef struct crypto_block_cipher_t {
    const crypto_block_cipher_vtable_t* vtable;
    const void* ctx;
} crypto_block_cipher_t;

#ifdef __cplusplus
}
#endif

#endif
