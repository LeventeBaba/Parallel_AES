#include "crypto_ocl_profile.h"

#include <string.h>

static crypto_ocl_profile_stats_t g_stats;

void crypto_ocl_profile_reset(void)
{
    memset(&g_stats, 0, sizeof(g_stats));
}

void crypto_ocl_profile_get(crypto_ocl_profile_stats_t* out)
{
    if (!out) {
        return;
    }
    *out = g_stats;
}

#ifdef CRYPTO_OCL_PROFILE
void crypto_ocl_profile_add_init(uint64_t total_ns,
                                 uint64_t choose_device_ns,
                                 uint64_t context_ns,
                                 uint64_t queue_ns,
                                 uint64_t round_keys_buffer_ns,
                                 uint64_t ctr_program_ns,
                                 uint64_t gcm_program_ns)
{
    g_stats.init_calls++;
    g_stats.init_ns += total_ns;
    g_stats.init_choose_device_ns += choose_device_ns;
    g_stats.init_context_ns += context_ns;
    g_stats.init_queue_ns += queue_ns;
    g_stats.init_round_keys_buffer_ns += round_keys_buffer_ns;
    g_stats.init_ctr_program_ns += ctr_program_ns;
    g_stats.init_gcm_program_ns += gcm_program_ns;
}

void crypto_ocl_profile_add_ensure_io(uint64_t ns, int reallocated, size_t requested_bytes)
{
    g_stats.ensure_io_calls++;
    g_stats.ensure_io_ns += ns;
    g_stats.ensure_io_requested_bytes += (uint64_t)requested_bytes;
    if (reallocated) {
        g_stats.ensure_io_reallocs++;
    }
}

void crypto_ocl_profile_add_ensure_ghash(uint64_t ns, int reallocated, size_t requested_bytes, size_t requested_chunks)
{
    g_stats.ensure_ghash_calls++;
    g_stats.ensure_ghash_ns += ns;
    g_stats.ensure_ghash_requested_bytes += (uint64_t)requested_bytes;
    g_stats.ensure_ghash_requested_chunks += (uint64_t)requested_chunks;
    if (reallocated) {
        g_stats.ensure_ghash_reallocs++;
    }
}

void crypto_ocl_profile_add_round_key_upload(uint64_t ns, int cache_hit)
{
    if (cache_hit) {
        g_stats.round_key_cache_hits++;
        return;
    }
    g_stats.round_key_upload_calls++;
    g_stats.round_key_upload_ns += ns;
}

void crypto_ocl_profile_add_ctr_total(uint64_t ns, size_t bytes)
{
    g_stats.ctr_calls++;
    g_stats.ctr_ns += ns;
    g_stats.ctr_bytes += (uint64_t)bytes;
}

void crypto_ocl_profile_add_ctr_host_to_device(uint64_t ns)
{
    g_stats.ctr_host_to_device_ns += ns;
}

void crypto_ocl_profile_add_ctr_set_args(uint64_t ns)
{
    g_stats.ctr_set_args_ns += ns;
}

void crypto_ocl_profile_add_ctr_kernel_enqueue(uint64_t ns, uint64_t device_ns)
{
    g_stats.ctr_kernel_enqueue_ns += ns;
    g_stats.ctr_kernel_device_ns += device_ns;
}

void crypto_ocl_profile_add_ctr_device_to_host(uint64_t ns)
{
    g_stats.ctr_device_to_host_ns += ns;
}

void crypto_ocl_profile_add_ctr_key_schedule(uint64_t ns)
{
    g_stats.ctr_key_schedule_calls++;
    g_stats.ctr_key_schedule_ns += ns;
}

void crypto_ocl_profile_add_ghash_total(uint64_t ns, size_t bytes)
{
    g_stats.ghash_calls++;
    g_stats.ghash_ns += ns;
    g_stats.ghash_bytes += (uint64_t)bytes;
}

void crypto_ocl_profile_add_ghash_host_to_device(uint64_t ns)
{
    g_stats.ghash_host_to_device_ns += ns;
}

void crypto_ocl_profile_add_ghash_device_copy(uint64_t ns)
{
    g_stats.ghash_device_copy_ns += ns;
}

void crypto_ocl_profile_add_ghash_set_args(uint64_t ns)
{
    g_stats.ghash_set_args_ns += ns;
}

void crypto_ocl_profile_add_ghash_kernel_enqueue(uint64_t ns, uint64_t device_ns)
{
    g_stats.ghash_kernel_enqueue_ns += ns;
    g_stats.ghash_kernel_device_ns += device_ns;
}

void crypto_ocl_profile_add_ghash_reduce_set_args(uint64_t ns)
{
    g_stats.ghash_reduce_set_args_ns += ns;
}

void crypto_ocl_profile_add_ghash_reduce_kernel_enqueue(uint64_t ns, uint64_t device_ns)
{
    g_stats.ghash_reduce_kernel_enqueue_ns += ns;
    g_stats.ghash_reduce_kernel_device_ns += device_ns;
}

void crypto_ocl_profile_add_ghash_device_to_host(uint64_t ns)
{
    g_stats.ghash_device_to_host_ns += ns;
}

void crypto_ocl_profile_add_ghash_reduce_device_to_host(uint64_t ns)
{
    g_stats.ghash_reduce_device_to_host_ns += ns;
}

void crypto_ocl_profile_add_ghash_cpu_reduce(uint64_t ns)
{
    g_stats.ghash_cpu_reduce_ns += ns;
}

void crypto_ocl_profile_add_gcm_encrypt_total(uint64_t ns, size_t bytes)
{
    g_stats.gcm_encrypt_calls++;
    g_stats.gcm_encrypt_ns += ns;
    g_stats.gcm_encrypt_bytes += (uint64_t)bytes;
}

void crypto_ocl_profile_add_gcm_decrypt_total(uint64_t ns, size_t bytes)
{
    g_stats.gcm_decrypt_calls++;
    g_stats.gcm_decrypt_ns += ns;
    g_stats.gcm_decrypt_bytes += (uint64_t)bytes;
}

void crypto_ocl_profile_add_gcm_cpu_prep(uint64_t ns)
{
    g_stats.gcm_cpu_prep_ns += ns;
}

void crypto_ocl_profile_add_gcm_ctr_stage(uint64_t ns)
{
    g_stats.gcm_ctr_stage_ns += ns;
}

void crypto_ocl_profile_add_gcm_ghash_stage(uint64_t ns)
{
    g_stats.gcm_ghash_stage_ns += ns;
}

void crypto_ocl_profile_add_gcm_tag_finalize(uint64_t ns)
{
    g_stats.gcm_tag_finalize_ns += ns;
}

void crypto_ocl_profile_add_gcm_auth_check(uint64_t ns)
{
    g_stats.gcm_auth_check_ns += ns;
}
#endif
