#ifndef CRYPTO_PROFILE_H
#define CRYPTO_PROFILE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct crypto_profile_stats_t {
    uint64_t aes_init_calls;
    uint64_t aes_init_ns;

    uint64_t aes_encrypt_block_calls;
    uint64_t aes_encrypt_block_ns;

    uint64_t aes_decrypt_block_calls;
    uint64_t aes_decrypt_block_ns;

    uint64_t aes_ctr_calls;
    uint64_t aes_ctr_ns;
    uint64_t aes_ctr_bytes;
    uint64_t aes_ctr_counter_ns;
    uint64_t aes_ctr_xor_ns;

    uint64_t aes_gcm_encrypt_calls;
    uint64_t aes_gcm_encrypt_ns;
    uint64_t aes_gcm_encrypt_bytes;

    uint64_t aes_gcm_decrypt_calls;
    uint64_t aes_gcm_decrypt_ns;
    uint64_t aes_gcm_decrypt_bytes;

    uint64_t aes_gcm_j0_ns;
    uint64_t aes_gcm_ctr_ns;
    uint64_t aes_gcm_auth_ns;
    uint64_t aes_gcm_auth_finalize_ns;

    uint64_t cbc_encrypt_calls;
    uint64_t cbc_encrypt_ns;
    uint64_t cbc_encrypt_bytes;

    uint64_t cbc_decrypt_calls;
    uint64_t cbc_decrypt_ns;
    uint64_t cbc_decrypt_bytes;

    uint64_t padding_apply_calls;
    uint64_t padding_apply_ns;

    uint64_t padding_remove_calls;
    uint64_t padding_remove_ns;

    uint64_t gf128_mul_calls;
    uint64_t gf128_mul_ns;

    uint64_t gf128_pow_calls;
    uint64_t gf128_pow_ns;
} crypto_profile_stats_t;

void crypto_profile_reset(void);
void crypto_profile_get(crypto_profile_stats_t* out);

#ifdef CRYPTO_PROFILE
void crypto_profile_add_aes_init(uint64_t ns);
void crypto_profile_add_aes_encrypt_block(uint64_t ns);
void crypto_profile_add_aes_decrypt_block(uint64_t ns);
void crypto_profile_add_aes_ctr(uint64_t ns, size_t bytes, uint64_t counter_ns, uint64_t xor_ns);
void crypto_profile_add_aes_gcm_encrypt(uint64_t ns, size_t bytes);
void crypto_profile_add_aes_gcm_decrypt(uint64_t ns, size_t bytes);
void crypto_profile_add_aes_gcm_j0(uint64_t ns);
void crypto_profile_add_aes_gcm_ctr(uint64_t ns);
void crypto_profile_add_aes_gcm_auth(uint64_t ns);
void crypto_profile_add_aes_gcm_auth_finalize(uint64_t ns);
void crypto_profile_add_cbc_encrypt(uint64_t ns, size_t bytes);
void crypto_profile_add_cbc_decrypt(uint64_t ns, size_t bytes);
void crypto_profile_add_padding_apply(uint64_t ns);
void crypto_profile_add_padding_remove(uint64_t ns);
void crypto_profile_add_gf128_mul(uint64_t ns);
void crypto_profile_add_gf128_pow(uint64_t ns);
#endif

#ifdef __cplusplus
}
#endif

#endif
