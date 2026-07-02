#ifndef CBC_H
#define CBC_H

#include <stddef.h>
#include <stdint.h>

#include "crypto_status.h"
#include "crypto_block_cipher.h"
#include "crypto_padding.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct crypto_cbc_t {
    crypto_block_cipher_t cipher;
    crypto_padding_t padding;
    uint8_t iv[16];
} crypto_cbc_t;

crypto_status_t crypto_cbc_init(crypto_cbc_t* cbc, crypto_block_cipher_t cipher, const uint8_t iv16[16], crypto_padding_t padding);

size_t crypto_cbc_ciphertext_size(const crypto_cbc_t* cbc, size_t plaintext_len);

crypto_status_t crypto_cbc_encrypt_buffer(const crypto_cbc_t* cbc,
                                         const uint8_t* plaintext,
                                         size_t plaintext_len,
                                         uint8_t* ciphertext,
                                         size_t ciphertext_capacity,
                                         size_t* ciphertext_len_out);

crypto_status_t crypto_cbc_decrypt_buffer(const crypto_cbc_t* cbc,
                                         const uint8_t* ciphertext,
                                         size_t ciphertext_len,
                                         uint8_t* plaintext,
                                         size_t plaintext_capacity,
                                         size_t* plaintext_len_out);

crypto_status_t crypto_cbc_encrypt_alloc(const crypto_cbc_t* cbc,
                                        const uint8_t* plaintext,
                                        size_t plaintext_len,
                                        uint8_t** ciphertext_out,
                                        size_t* ciphertext_len_out);

crypto_status_t crypto_cbc_decrypt_alloc(const crypto_cbc_t* cbc,
                                        const uint8_t* ciphertext,
                                        size_t ciphertext_len,
                                        uint8_t** plaintext_out,
                                        size_t* plaintext_len_out);

crypto_status_t crypto_cbc_encrypt_file(const crypto_cbc_t* cbc,
                                       const char* input_path,
                                       const char* output_path,
                                       int prefix_iv);

crypto_status_t crypto_cbc_decrypt_file(const crypto_cbc_t* cbc,
                                       const char* input_path,
                                       const char* output_path,
                                       int prefix_iv);

#ifdef __cplusplus
}
#endif

#endif
