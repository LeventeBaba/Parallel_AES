#ifndef CRYPTO_OCL_PROFILE_H
#define CRYPTO_OCL_PROFILE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct crypto_ocl_profile_stats_t {
    uint64_t init_calls;
    uint64_t init_ns;
    uint64_t init_choose_device_ns;
    uint64_t init_context_ns;
    uint64_t init_queue_ns;
    uint64_t init_round_keys_buffer_ns;
    uint64_t init_ctr_program_ns;
    uint64_t init_gcm_program_ns;

    uint64_t ensure_io_calls;
    uint64_t ensure_io_ns;
    uint64_t ensure_io_reallocs;
    uint64_t ensure_io_requested_bytes;

    uint64_t ensure_ghash_calls;
    uint64_t ensure_ghash_ns;
    uint64_t ensure_ghash_reallocs;
    uint64_t ensure_ghash_requested_bytes;
    uint64_t ensure_ghash_requested_chunks;

    uint64_t round_key_upload_calls;
    uint64_t round_key_upload_ns;
    uint64_t round_key_cache_hits;

    uint64_t ctr_calls;
    uint64_t ctr_ns;
    uint64_t ctr_bytes;
    uint64_t ctr_host_to_device_ns;
    uint64_t ctr_set_args_ns;
    uint64_t ctr_kernel_enqueue_ns;
    uint64_t ctr_kernel_device_ns;
    uint64_t ctr_device_to_host_ns;

    uint64_t ctr_key_schedule_calls;
    uint64_t ctr_key_schedule_ns;

    uint64_t ghash_calls;
    uint64_t ghash_ns;
    uint64_t ghash_bytes;
    uint64_t ghash_host_to_device_ns;
    uint64_t ghash_device_copy_ns;
    uint64_t ghash_set_args_ns;
    uint64_t ghash_kernel_enqueue_ns;
    uint64_t ghash_kernel_device_ns;
    uint64_t ghash_reduce_set_args_ns;
    uint64_t ghash_reduce_kernel_enqueue_ns;
    uint64_t ghash_reduce_kernel_device_ns;
    uint64_t ghash_device_to_host_ns;
    uint64_t ghash_reduce_device_to_host_ns;
    uint64_t ghash_cpu_reduce_ns;

    uint64_t gcm_encrypt_calls;
    uint64_t gcm_encrypt_ns;
    uint64_t gcm_encrypt_bytes;

    uint64_t gcm_decrypt_calls;
    uint64_t gcm_decrypt_ns;
    uint64_t gcm_decrypt_bytes;

    uint64_t gcm_cpu_prep_ns;
    uint64_t gcm_ctr_stage_ns;
    uint64_t gcm_ghash_stage_ns;
    uint64_t gcm_tag_finalize_ns;
    uint64_t gcm_auth_check_ns;
} crypto_ocl_profile_stats_t;

void crypto_ocl_profile_reset(void);
void crypto_ocl_profile_get(crypto_ocl_profile_stats_t* out);

#ifdef CRYPTO_OCL_PROFILE
void crypto_ocl_profile_add_init(uint64_t total_ns,
                                 uint64_t choose_device_ns,
                                 uint64_t context_ns,
                                 uint64_t queue_ns,
                                 uint64_t round_keys_buffer_ns,
                                 uint64_t ctr_program_ns,
                                 uint64_t gcm_program_ns);
void crypto_ocl_profile_add_ensure_io(uint64_t ns, int reallocated, size_t requested_bytes);
void crypto_ocl_profile_add_ensure_ghash(uint64_t ns, int reallocated, size_t requested_bytes, size_t requested_chunks);
void crypto_ocl_profile_add_round_key_upload(uint64_t ns, int cache_hit);
void crypto_ocl_profile_add_ctr_total(uint64_t ns, size_t bytes);
void crypto_ocl_profile_add_ctr_host_to_device(uint64_t ns);
void crypto_ocl_profile_add_ctr_set_args(uint64_t ns);
void crypto_ocl_profile_add_ctr_kernel_enqueue(uint64_t ns, uint64_t device_ns);
void crypto_ocl_profile_add_ctr_device_to_host(uint64_t ns);
void crypto_ocl_profile_add_ctr_key_schedule(uint64_t ns);
void crypto_ocl_profile_add_ghash_total(uint64_t ns, size_t bytes);
void crypto_ocl_profile_add_ghash_host_to_device(uint64_t ns);
void crypto_ocl_profile_add_ghash_device_copy(uint64_t ns);
void crypto_ocl_profile_add_ghash_set_args(uint64_t ns);
void crypto_ocl_profile_add_ghash_kernel_enqueue(uint64_t ns, uint64_t device_ns);
void crypto_ocl_profile_add_ghash_reduce_set_args(uint64_t ns);
void crypto_ocl_profile_add_ghash_reduce_kernel_enqueue(uint64_t ns, uint64_t device_ns);
void crypto_ocl_profile_add_ghash_device_to_host(uint64_t ns);
void crypto_ocl_profile_add_ghash_reduce_device_to_host(uint64_t ns);
void crypto_ocl_profile_add_ghash_cpu_reduce(uint64_t ns);
void crypto_ocl_profile_add_gcm_encrypt_total(uint64_t ns, size_t bytes);
void crypto_ocl_profile_add_gcm_decrypt_total(uint64_t ns, size_t bytes);
void crypto_ocl_profile_add_gcm_cpu_prep(uint64_t ns);
void crypto_ocl_profile_add_gcm_ctr_stage(uint64_t ns);
void crypto_ocl_profile_add_gcm_ghash_stage(uint64_t ns);
void crypto_ocl_profile_add_gcm_tag_finalize(uint64_t ns);
void crypto_ocl_profile_add_gcm_auth_check(uint64_t ns);
#endif

#ifdef __cplusplus
}
#endif

#endif
