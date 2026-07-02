#ifndef OPENCL_AES_CTR_H
#define OPENCL_AES_CTR_H

#include <stddef.h>
#include <stdint.h>

#include "crypto_status.h"

#ifdef __cplusplus
extern "C" {
#endif

crypto_status_t crypto_ocl_aes_ctr_xor_round_keys(const uint8_t* round_keys,
                                                 size_t round_keys_len,
                                                 const uint8_t iv16[16],
                                                 const uint8_t* input,
                                                 uint8_t* output,
                                                 size_t len,
                                                 uint64_t block_offset,
                                                 uint64_t* out_kernel_ns);

crypto_status_t crypto_ocl_aes_ctr_xor(const uint8_t* key,
                                      size_t key_len_bytes,
                                      const uint8_t iv16[16],
                                      const uint8_t* input,
                                      uint8_t* output,
                                      size_t len,
                                      uint64_t block_offset,
                                      uint64_t* out_kernel_ns);

const char* crypto_ocl_last_error_message(void);
const char* crypto_ocl_platform_name(void);
const char* crypto_ocl_platform_version(void);
const char* crypto_ocl_device_name(void);
const char* crypto_ocl_device_version(void);
const char* crypto_ocl_device_opencl_c_version(void);
void crypto_ocl_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif
