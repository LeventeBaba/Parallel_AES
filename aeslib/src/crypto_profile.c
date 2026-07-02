#include "crypto_profile.h"

#include <string.h>

static crypto_profile_stats_t g_stats;

void crypto_profile_reset(void)
{
    memset(&g_stats, 0, sizeof(g_stats));
}

void crypto_profile_get(crypto_profile_stats_t* out)
{
    if (!out) {
        return;
    }
    *out = g_stats;
}

#ifdef CRYPTO_PROFILE
void crypto_profile_add_aes_init(uint64_t ns)
{
    g_stats.aes_init_calls++;
    g_stats.aes_init_ns += ns;
}

void crypto_profile_add_aes_encrypt_block(uint64_t ns)
{
    g_stats.aes_encrypt_block_calls++;
    g_stats.aes_encrypt_block_ns += ns;
}

void crypto_profile_add_aes_decrypt_block(uint64_t ns)
{
    g_stats.aes_decrypt_block_calls++;
    g_stats.aes_decrypt_block_ns += ns;
}

void crypto_profile_add_aes_ctr(uint64_t ns, size_t bytes, uint64_t counter_ns, uint64_t xor_ns)
{
    g_stats.aes_ctr_calls++;
    g_stats.aes_ctr_ns += ns;
    g_stats.aes_ctr_bytes += (uint64_t)bytes;
    g_stats.aes_ctr_counter_ns += counter_ns;
    g_stats.aes_ctr_xor_ns += xor_ns;
}

void crypto_profile_add_aes_gcm_encrypt(uint64_t ns, size_t bytes)
{
    g_stats.aes_gcm_encrypt_calls++;
    g_stats.aes_gcm_encrypt_ns += ns;
    g_stats.aes_gcm_encrypt_bytes += (uint64_t)bytes;
}

void crypto_profile_add_aes_gcm_decrypt(uint64_t ns, size_t bytes)
{
    g_stats.aes_gcm_decrypt_calls++;
    g_stats.aes_gcm_decrypt_ns += ns;
    g_stats.aes_gcm_decrypt_bytes += (uint64_t)bytes;
}

void crypto_profile_add_aes_gcm_j0(uint64_t ns)
{
    g_stats.aes_gcm_j0_ns += ns;
}

void crypto_profile_add_aes_gcm_ctr(uint64_t ns)
{
    g_stats.aes_gcm_ctr_ns += ns;
}

void crypto_profile_add_aes_gcm_auth(uint64_t ns)
{
    g_stats.aes_gcm_auth_ns += ns;
}

void crypto_profile_add_aes_gcm_auth_finalize(uint64_t ns)
{
    g_stats.aes_gcm_auth_finalize_ns += ns;
}

void crypto_profile_add_cbc_encrypt(uint64_t ns, size_t bytes)
{
    g_stats.cbc_encrypt_calls++;
    g_stats.cbc_encrypt_ns += ns;
    g_stats.cbc_encrypt_bytes += (uint64_t)bytes;
}

void crypto_profile_add_cbc_decrypt(uint64_t ns, size_t bytes)
{
    g_stats.cbc_decrypt_calls++;
    g_stats.cbc_decrypt_ns += ns;
    g_stats.cbc_decrypt_bytes += (uint64_t)bytes;
}

void crypto_profile_add_padding_apply(uint64_t ns)
{
    g_stats.padding_apply_calls++;
    g_stats.padding_apply_ns += ns;
}

void crypto_profile_add_padding_remove(uint64_t ns)
{
    g_stats.padding_remove_calls++;
    g_stats.padding_remove_ns += ns;
}

void crypto_profile_add_gf128_mul(uint64_t ns)
{
    g_stats.gf128_mul_calls++;
    g_stats.gf128_mul_ns += ns;
}

void crypto_profile_add_gf128_pow(uint64_t ns)
{
    g_stats.gf128_pow_calls++;
    g_stats.gf128_pow_ns += ns;
}
#endif
