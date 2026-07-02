#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "aes_ctr.h"
#include "aes_gcm.h"
#include "crypto_timer.h"
#include "opencl_aes_ctr.h"
#include "opencl_aes_gcm.h"
#include "crypto_ffi_opencl.h"

static void fill_data(uint8_t* p, size_t n)
{
    uint32_t x = 0x12345678u;
    for (size_t i = 0; i < n; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        p[i] = (uint8_t)x;
    }
}

static double ns_to_ms(uint64_t ns)
{
    return (double)ns / 1000000.0;
}

static double bytes_to_mib(size_t n)
{
    return (double)n / (1024.0 * 1024.0);
}

static void bench_one(const uint8_t* key, size_t key_len, const uint8_t iv[16], const uint8_t* input, uint8_t* out_cpu, uint8_t* out_gpu, size_t len, int iters)
{
    uint64_t best_cpu = (uint64_t)-1;
    uint64_t best_gpu = (uint64_t)-1;
    uint64_t best_kernel = 0;

    {
        crypto_aes_t aes;
        crypto_status_t st = crypto_aes_init(&aes, key, key_len);
        if (st != CRYPTO_OK) {
            printf("CPU AES init failed: %d\n", (int)st);
            exit(2);
        }

        for (int i = 0; i < iters; i++) {
            uint64_t t0 = crypto_time_now_ns();
            st = crypto_aes_ctr_xor_aes(&aes, iv, input, out_cpu, len, 0);
            uint64_t t1 = crypto_time_now_ns();
            if (st != CRYPTO_OK) {
                printf("CPU CTR failed: %d\n", (int)st);
                crypto_aes_clear(&aes);
                exit(2);
            }
            uint64_t dt = t1 - t0;
            if (dt < best_cpu) {
                best_cpu = dt;
            }
        }

        crypto_aes_clear(&aes);
    }

    for (int i = 0; i < iters; i++) {
        uint64_t kernel_ns = 0;
        uint64_t t0 = crypto_time_now_ns();
        crypto_status_t st = crypto_ocl_aes_ctr_xor(key, key_len, iv, input, out_gpu, len, 0, &kernel_ns);
        uint64_t t1 = crypto_time_now_ns();
        if (st != CRYPTO_OK) {
            printf("GPU encrypt failed: %d\n", (int)st);
            printf("OpenCL error: %s\n", crypto_ocl_last_error_message());
            exit(3);
        }
        uint64_t dt = t1 - t0;
        if (dt < best_gpu) {
            best_gpu = dt;
            best_kernel = kernel_ns;
        }
    }

    if (memcmp(out_cpu, out_gpu, len) != 0) {
        printf("Output mismatch between CPU and GPU\n");
        exit(4);
    }

    int key_bits = (int)(key_len * 8);

    printf("\nAES-%d\n", key_bits);
    printf("CPU best: %.3f ms (%.2f MiB/s)\n", ns_to_ms(best_cpu), bytes_to_mib(len) / (ns_to_ms(best_cpu) / 1000.0));
    printf("GPU best (end-to-end): %.3f ms (%.2f MiB/s)\n", ns_to_ms(best_gpu), bytes_to_mib(len) / (ns_to_ms(best_gpu) / 1000.0));
    printf("Speedup: %.2fx\n", (double)best_cpu / (double)best_gpu);

#ifdef CRYPTO_OCL_PROFILE
    if (best_kernel) {
        printf("GPU kernel only: %.3f ms\n", ns_to_ms(best_kernel));
    }
#else
    (void)best_kernel;
#endif
}

static void bench_one_gcm(const uint8_t* key, size_t key_len, const uint8_t iv12[12], const uint8_t* input, uint8_t* out_cpu, uint8_t* out_gpu, size_t len, int iters)
{
    uint64_t best_cpu = (uint64_t)-1;
    uint64_t best_gpu = (uint64_t)-1;
    uint64_t best_kernel = 0;

    uint8_t tag_cpu[16];
    uint8_t tag_gpu[16];

    for (int i = 0; i < iters; i++) {
        uint64_t t0 = crypto_time_now_ns();
        crypto_status_t st = crypto_aes_gcm_encrypt(key, key_len, iv12, 12, NULL, 0, input, len, out_cpu, tag_cpu);
        uint64_t t1 = crypto_time_now_ns();
        if (st != CRYPTO_OK) {
            printf("CPU GCM failed: %d\n", (int)st);
            exit(2);
        }
        uint64_t dt = t1 - t0;
        if (dt < best_cpu) {
            best_cpu = dt;
        }
    }

    for (int i = 0; i < iters; i++) {
        uint64_t kernel_ns = 0;
        uint64_t t0 = crypto_time_now_ns();
        crypto_status_t st = crypto_ocl_aes_gcm_encrypt(key, key_len, iv12, 12, NULL, 0, input, len, out_gpu, tag_gpu, &kernel_ns);
        uint64_t t1 = crypto_time_now_ns();
        if (st != CRYPTO_OK) {
            printf("GPU GCM failed: %d\n", (int)st);
            printf("OpenCL error: %s\n", crypto_ocl_last_error_message());
            exit(3);
        }
        uint64_t dt = t1 - t0;
        if (dt < best_gpu) {
            best_gpu = dt;
            best_kernel = kernel_ns;
        }
    }
    if (memcmp(out_cpu, out_gpu, len) != 0) {
        size_t first = 0;
        for (size_t i = 0; i < len; i++) {
            if (out_cpu[i] != out_gpu[i]) {
                first = i;
                break;
            }
        }
        printf("GCM ciphertext mismatch between CPU and GPU (first diff at byte %zu)\n", first);
        exit(4);
    }

    if (memcmp(tag_cpu, tag_gpu, 16) != 0) {
        printf("GCM tag mismatch between CPU and GPU\n");
        printf("CPU tag: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", (unsigned)tag_cpu[i]);
        }
        printf("\nGPU tag: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", (unsigned)tag_gpu[i]);
        }
        printf("\n");
        exit(4);
    }

    int key_bits = (int)(key_len * 8);

    printf("\nAES-%d-GCM\n", key_bits);
    printf("CPU best: %.3f ms (%.2f MiB/s)\n", ns_to_ms(best_cpu), bytes_to_mib(len) / (ns_to_ms(best_cpu) / 1000.0));
    printf("GPU best (end-to-end): %.3f ms (%.2f MiB/s)\n", ns_to_ms(best_gpu), bytes_to_mib(len) / (ns_to_ms(best_gpu) / 1000.0));
    printf("Speedup: %.2fx\n", (double)best_cpu / (double)best_gpu);

#ifdef CRYPTO_OCL_PROFILE
    if (best_kernel) {
        printf("GPU kernels only: %.3f ms\n", ns_to_ms(best_kernel));
    }
#else
    (void)best_kernel;
#endif
}

int main(int argc, char** argv)
{
    size_t len = 256u * 1024u * 1024u;
    int iters = 3;

    if (argc >= 2) {
        unsigned long long v = strtoull(argv[1], NULL, 10);
        if (v > 0) {
            len = (size_t)v;
        }
    }

    if (argc >= 3) {
        int v = atoi(argv[2]);
        if (v > 0) {
            iters = v;
        }
    }

    if (len < 16) {
        len = 16;
    }

    {
        size_t rem = len % 16;
        if (rem) {
            len -= rem;
        }
    }

    uint8_t iv[16];
    uint8_t iv12[12];
    uint8_t key128[16];
    uint8_t key192[24];
    uint8_t key256[32];

    fill_data(iv, sizeof(iv));
    fill_data(iv12, sizeof(iv12));
    fill_data(key128, sizeof(key128));
    fill_data(key192, sizeof(key192));
    fill_data(key256, sizeof(key256));

    uint8_t* input = (uint8_t*)malloc(len);
    uint8_t* out_cpu = (uint8_t*)malloc(len);
    uint8_t* out_gpu = (uint8_t*)malloc(len);

    if (!input || !out_cpu || !out_gpu) {
        printf("Allocation failed\n");
        free(input);
        free(out_cpu);
        free(out_gpu);
        return 1;
    }

    fill_data(input, len);

    if (crypto_ffi_opencl_warmup() != CRYPTO_OK) {
        printf("OpenCL warmup failed\n");
        printf("OpenCL error: %s\n", crypto_ffi_opencl_last_error_message());
        free(input);
        free(out_cpu);
        free(out_gpu);
        return 2;
    }

    printf("Data: %.2f MiB\n", bytes_to_mib(len));

    printf("\n=== AES-CTR (encrypt: XOR with keystream) ===\n");

    bench_one(key128, sizeof(key128), iv, input, out_cpu, out_gpu, len, iters);
    bench_one(key192, sizeof(key192), iv, input, out_cpu, out_gpu, len, iters);
    bench_one(key256, sizeof(key256), iv, input, out_cpu, out_gpu, len, iters);

    printf("\n=== AES-GCM (encrypt + tag, AAD=0, IV=12 bytes) ===\n");

    bench_one_gcm(key128, sizeof(key128), iv12, input, out_cpu, out_gpu, len, iters);
    bench_one_gcm(key192, sizeof(key192), iv12, input, out_cpu, out_gpu, len, iters);
    bench_one_gcm(key256, sizeof(key256), iv12, input, out_cpu, out_gpu, len, iters);

    free(input);
    free(out_cpu);
    free(out_gpu);
    return 0;
}
