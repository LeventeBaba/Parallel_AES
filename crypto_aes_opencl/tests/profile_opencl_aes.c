#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "aes_gcm.h"
#include "crypto_profile.h"
#include "crypto_timer.h"
#include "crypto_ocl_profile.h"
#include "opencl_aes_ctr.h"
#include "opencl_aes_gcm.h"

typedef struct metric_item_t {
    const char* name;
    uint64_t ns;
} metric_item_t;

static uint32_t prng_next(uint32_t x)
{
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x;
}

static void fill_random(uint8_t* p, size_t n)
{
    uint32_t x = 0x89ABCDEFu;
    for (size_t i = 0; i < n; i++) {
        x = prng_next(x);
        p[i] = (uint8_t)(x & 0xFFu);
    }
}

static double ns_to_ms(uint64_t ns)
{
    return (double)ns / 1000000.0;
}

static double bytes_to_mib(size_t bytes)
{
    return (double)bytes / (1024.0 * 1024.0);
}

static double throughput_mib_s(size_t bytes, uint64_t ns)
{
    double seconds = (double)ns / 1000000000.0;
    if (seconds <= 0.0) {
        return 0.0;
    }
    return bytes_to_mib(bytes) / seconds;
}

static int cmp_metric_desc(const void* a, const void* b)
{
    const metric_item_t* ma = (const metric_item_t*)a;
    const metric_item_t* mb = (const metric_item_t*)b;
    if (ma->ns < mb->ns) {
        return 1;
    }
    if (ma->ns > mb->ns) {
        return -1;
    }
    return 0;
}

static void print_ranked_breakdown(const char* title, uint64_t total_ns, const metric_item_t* items, size_t count)
{
    metric_item_t tmp[16];
    size_t used = 0;
    for (size_t i = 0; i < count && used < (sizeof(tmp) / sizeof(tmp[0])); i++) {
        if (items[i].ns == 0) {
            continue;
        }
        tmp[used++] = items[i];
    }
    qsort(tmp, used, sizeof(tmp[0]), cmp_metric_desc);

    printf("%s\n", title);
    for (size_t i = 0; i < used; i++) {
        double pct = total_ns ? ((double)tmp[i].ns * 100.0 / (double)total_ns) : 0.0;
        printf("  %-28s %9.3f ms  %6.2f%%\n", tmp[i].name, ns_to_ms(tmp[i].ns), pct);
    }
}

static void print_cpu_helper_hotspots(const crypto_profile_stats_t* stats, uint64_t total_ns)
{
    metric_item_t items[4];
    items[0].name = "AES key expansion";
    items[0].ns = stats->aes_init_ns;
    items[1].name = "AES block encrypt";
    items[1].ns = stats->aes_encrypt_block_ns;
    items[2].name = "GF128 multiply";
    items[2].ns = stats->gf128_mul_ns;
    items[3].name = "GF128 power";
    items[3].ns = stats->gf128_pow_ns;
    print_ranked_breakdown("CPU-side helper hotspots:", total_ns, items, 4);
}

static void print_opencl_hints_ctr(const crypto_ocl_profile_stats_t* stats)
{
    uint64_t total = stats->ctr_key_schedule_ns + stats->ctr_ns;
    uint64_t transfers = stats->ctr_host_to_device_ns + stats->ctr_device_to_host_ns;
    printf("Likely bottlenecks:\n");
    if (transfers > stats->ctr_kernel_device_ns) {
        printf("  Host-device transfer time is larger than device kernel time. Larger batches or buffer reuse should help first.\n");
    }
    if (stats->ctr_kernel_device_ns * 100 >= total * 35) {
        printf("  The OpenCL kernel itself is substantial. Kernel-level optimization can still matter.\n");
    }
    if (stats->ctr_key_schedule_ns * 100 >= total * 10) {
        printf("  CPU key expansion is visible. Reusing expanded round keys would reduce overhead.\n");
    }
    if (stats->round_key_upload_ns && stats->round_key_cache_hits == 0) {
        printf("  Round-key uploads are not cached in this run. Reusing the same key reduces setup cost.\n");
    }
}

static void print_opencl_hints_gcm(const crypto_ocl_profile_stats_t* stats, const crypto_profile_stats_t* cpu_stats, int decrypt_mode)
{
    uint64_t total = decrypt_mode ? stats->gcm_decrypt_ns : stats->gcm_encrypt_ns;
    uint64_t transfers = stats->ctr_host_to_device_ns + stats->ctr_device_to_host_ns +
                         stats->ghash_host_to_device_ns + stats->ghash_device_to_host_ns +
                         stats->ghash_reduce_device_to_host_ns;
    uint64_t kernels = stats->ctr_kernel_device_ns + stats->ghash_kernel_device_ns + stats->ghash_reduce_kernel_device_ns;
    printf("Likely bottlenecks:\n");
    if (stats->gcm_ghash_stage_ns > stats->gcm_ctr_stage_ns) {
        printf("  GHASH is still the dominant stage. The next wins are inside the GHASH kernels or by reducing GHASH-side copies further.\n");
    }
    if (stats->ghash_device_copy_ns * 100 >= total * 8) {
        printf("  Device-to-device GHASH assembly is now visible. A fused GHASH path that reads ciphertext directly could help further.\n");
    }
    if (transfers > kernels) {
        printf("  Data transfers are still heavier than combined kernel execution. The GPU path remains at least partly transfer-bound.\n");
    }
    if (stats->ghash_reduce_kernel_device_ns * 100 >= total * 8) {
        printf("  The on-device GHASH reduction is now measurable. Larger GHASH chunks may reduce this combine cost further.\n");
    }
    if (stats->ghash_cpu_reduce_ns == 0 && (stats->ghash_reduce_kernel_device_ns || stats->ghash_device_copy_ns)) {
        printf("  The old CPU-side GHASH reduction is no longer a hotspot in this build. Most remaining GHASH work is now on the device side.\n");
    }
    if (cpu_stats->gf128_mul_ns || cpu_stats->gf128_pow_ns) {
        printf("  CPU helper work is now minor. The best remaining optimizations are in OpenCL data flow and GHASH kernel structure.\n");
    }
}

static int run_cold_init_profile(const uint8_t* key,
                                 size_t key_len,
                                 const uint8_t iv[16],
                                 const uint8_t* input,
                                 uint8_t* output,
                                 size_t len)
{
    crypto_ocl_profile_stats_t ocl_stats;
    crypto_profile_stats_t cpu_stats;
    uint64_t wall_ns;
    crypto_status_t st;

    crypto_ocl_shutdown();
    crypto_ocl_profile_reset();
    crypto_profile_reset();

    wall_ns = crypto_time_now_ns();
    st = crypto_ocl_aes_ctr_xor(key, key_len, iv, input, output, len, 0, NULL);
    wall_ns = crypto_time_now_ns() - wall_ns;
    if (st != CRYPTO_OK) {
        printf("Cold-start OpenCL warmup failed: %d\n", (int)st);
        printf("OpenCL error: %s\n", crypto_ocl_last_error_message());
        return 0;
    }

    crypto_ocl_profile_get(&ocl_stats);
    crypto_profile_get(&cpu_stats);

    printf("\n=== OpenCL cold-start profile ===\n");
    printf("End-to-end wall time: %.3f ms\n", ns_to_ms(wall_ns));
    printf("Init only: %.3f ms\n", ns_to_ms(ocl_stats.init_ns));

    {
        uint64_t other = ocl_stats.init_ns;
        metric_item_t items[7];

        if (other >= ocl_stats.init_choose_device_ns) other -= ocl_stats.init_choose_device_ns; else other = 0;
        if (other >= ocl_stats.init_context_ns) other -= ocl_stats.init_context_ns; else other = 0;
        if (other >= ocl_stats.init_queue_ns) other -= ocl_stats.init_queue_ns; else other = 0;
        if (other >= ocl_stats.init_round_keys_buffer_ns) other -= ocl_stats.init_round_keys_buffer_ns; else other = 0;
        if (other >= ocl_stats.init_ctr_program_ns) other -= ocl_stats.init_ctr_program_ns; else other = 0;
        if (other >= ocl_stats.init_gcm_program_ns) other -= ocl_stats.init_gcm_program_ns; else other = 0;

        items[0].name = "Choose platform/device";
        items[0].ns = ocl_stats.init_choose_device_ns;
        items[1].name = "Create context";
        items[1].ns = ocl_stats.init_context_ns;
        items[2].name = "Create queue";
        items[2].ns = ocl_stats.init_queue_ns;
        items[3].name = "Round-key buffer";
        items[3].ns = ocl_stats.init_round_keys_buffer_ns;
        items[4].name = "Build CTR program";
        items[4].ns = ocl_stats.init_ctr_program_ns;
        items[5].name = "Build GHASH program";
        items[5].ns = ocl_stats.init_gcm_program_ns;
        items[6].name = "Other init work";
        items[6].ns = other;
        print_ranked_breakdown("Initialization breakdown:", ocl_stats.init_ns, items, 7);
    }

    print_cpu_helper_hotspots(&cpu_stats, wall_ns);
    return 1;
}

static int run_warm_ctr_profile(const uint8_t* key,
                                size_t key_len,
                                const uint8_t iv[16],
                                const uint8_t* input,
                                uint8_t* output,
                                size_t len,
                                int iters)
{
    crypto_ocl_profile_stats_t ocl_stats;
    crypto_profile_stats_t cpu_stats;
    uint64_t wall_ns = 0;

    crypto_ocl_profile_reset();
    crypto_profile_reset();
    for (int i = 0; i < iters; i++) {
        uint64_t t0 = crypto_time_now_ns();
        crypto_status_t st = crypto_ocl_aes_ctr_xor(key, key_len, iv, input, output, len, 0, NULL);
        wall_ns += crypto_time_now_ns() - t0;
        if (st != CRYPTO_OK) {
            printf("Warm CTR failed: %d\n", (int)st);
            printf("OpenCL error: %s\n", crypto_ocl_last_error_message());
            return 0;
        }
    }

    crypto_ocl_profile_get(&ocl_stats);
    crypto_profile_get(&cpu_stats);

    printf("\n=== OpenCL AES-CTR warm profile ===\n");
    printf("Iterations: %d\n", iters);
    printf("Average wall time: %.3f ms\n", ns_to_ms(wall_ns / (uint64_t)iters));
    printf("Average throughput: %.2f MiB/s\n", throughput_mib_s(len, wall_ns / (uint64_t)iters));

    {
        uint64_t total = ocl_stats.ctr_key_schedule_ns + ocl_stats.ctr_ns;
        uint64_t other = total;
        metric_item_t items[8];

        if (other >= ocl_stats.ctr_key_schedule_ns) other -= ocl_stats.ctr_key_schedule_ns; else other = 0;
        if (other >= ocl_stats.ensure_io_ns) other -= ocl_stats.ensure_io_ns; else other = 0;
        if (other >= ocl_stats.round_key_upload_ns) other -= ocl_stats.round_key_upload_ns; else other = 0;
        if (other >= ocl_stats.ctr_host_to_device_ns) other -= ocl_stats.ctr_host_to_device_ns; else other = 0;
        if (other >= ocl_stats.ctr_set_args_ns) other -= ocl_stats.ctr_set_args_ns; else other = 0;
        if (other >= ocl_stats.ctr_kernel_device_ns) other -= ocl_stats.ctr_kernel_device_ns; else other = 0;
        if (other >= ocl_stats.ctr_device_to_host_ns) other -= ocl_stats.ctr_device_to_host_ns; else other = 0;

        items[0].name = "CPU key expansion";
        items[0].ns = ocl_stats.ctr_key_schedule_ns;
        items[1].name = "Ensure IO buffers";
        items[1].ns = ocl_stats.ensure_io_ns;
        items[2].name = "Upload round keys";
        items[2].ns = ocl_stats.round_key_upload_ns;
        items[3].name = "Host to device copy";
        items[3].ns = ocl_stats.ctr_host_to_device_ns;
        items[4].name = "Kernel arg setup";
        items[4].ns = ocl_stats.ctr_set_args_ns;
        items[5].name = "Device kernel time";
        items[5].ns = ocl_stats.ctr_kernel_device_ns;
        items[6].name = "Device to host copy";
        items[6].ns = ocl_stats.ctr_device_to_host_ns;
        items[7].name = "Other host overhead";
        items[7].ns = other;

        print_ranked_breakdown("Breakdown:", total, items, 8);
    }

    printf("Round-key cache hits: %llu\n", (unsigned long long)ocl_stats.round_key_cache_hits);
    print_cpu_helper_hotspots(&cpu_stats, ocl_stats.ctr_key_schedule_ns + ocl_stats.ctr_ns);
    print_opencl_hints_ctr(&ocl_stats);
    return 1;
}

static int run_warm_gcm_profile(const uint8_t* key,
                                size_t key_len,
                                const uint8_t iv12[12],
                                const uint8_t* input,
                                uint8_t* output,
                                size_t len,
                                int iters,
                                int decrypt_mode)
{
    crypto_ocl_profile_stats_t ocl_stats;
    crypto_profile_stats_t cpu_stats;
    uint64_t wall_ns = 0;
    uint8_t tag[16];
    uint8_t* ciphertext = NULL;
    crypto_status_t st;

    if (decrypt_mode) {
        ciphertext = (uint8_t*)malloc(len ? len : 1u);
        if (!ciphertext) {
            printf("Allocation failed for decrypt profile\n");
            return 0;
        }
        st = crypto_aes_gcm_encrypt(key, key_len, iv12, 12, NULL, 0, input, len, ciphertext, tag);
        if (st != CRYPTO_OK) {
            printf("GCM setup encrypt failed: %d\n", (int)st);
            free(ciphertext);
            return 0;
        }
    }

    crypto_ocl_profile_reset();
    crypto_profile_reset();
    for (int i = 0; i < iters; i++) {
        uint64_t t0 = crypto_time_now_ns();
        if (decrypt_mode) {
            st = crypto_ocl_aes_gcm_decrypt(key, key_len, iv12, 12, NULL, 0, ciphertext, len, tag, output, NULL);
        } else {
            st = crypto_ocl_aes_gcm_encrypt(key, key_len, iv12, 12, NULL, 0, input, len, output, tag, NULL);
        }
        wall_ns += crypto_time_now_ns() - t0;
        if (st != CRYPTO_OK) {
            printf("OpenCL AES-GCM %s failed: %d\n", decrypt_mode ? "decrypt" : "encrypt", (int)st);
            printf("OpenCL error: %s\n", crypto_ocl_last_error_message());
            return 0;
        }
    }

    crypto_ocl_profile_get(&ocl_stats);
    crypto_profile_get(&cpu_stats);

    printf("\n=== OpenCL AES-GCM %s warm profile ===\n", decrypt_mode ? "decrypt" : "encrypt");
    printf("Iterations: %d\n", iters);
    printf("Average wall time: %.3f ms\n", ns_to_ms(wall_ns / (uint64_t)iters));
    printf("Average throughput: %.2f MiB/s\n", throughput_mib_s(len, wall_ns / (uint64_t)iters));

    {
        uint64_t total = decrypt_mode ? ocl_stats.gcm_decrypt_ns : ocl_stats.gcm_encrypt_ns;
        uint64_t known = ocl_stats.gcm_cpu_prep_ns + ocl_stats.gcm_ctr_stage_ns + ocl_stats.gcm_ghash_stage_ns +
                         ocl_stats.gcm_tag_finalize_ns + (decrypt_mode ? ocl_stats.gcm_auth_check_ns : 0);
        uint64_t other = (total >= known) ? (total - known) : 0;
        metric_item_t items[6];

        items[0].name = "CPU preparation";
        items[0].ns = ocl_stats.gcm_cpu_prep_ns;
        items[1].name = "CTR stage";
        items[1].ns = ocl_stats.gcm_ctr_stage_ns;
        items[2].name = "GHASH stage";
        items[2].ns = ocl_stats.gcm_ghash_stage_ns;
        items[3].name = "Tag finalize";
        items[3].ns = ocl_stats.gcm_tag_finalize_ns;
        items[4].name = "Auth check";
        items[4].ns = decrypt_mode ? ocl_stats.gcm_auth_check_ns : 0;
        items[5].name = "Other host overhead";
        items[5].ns = other;
        print_ranked_breakdown("Top-level stages:", total, items, 6);
    }

    {
        uint64_t total = decrypt_mode ? ocl_stats.gcm_decrypt_ns : ocl_stats.gcm_encrypt_ns;
        metric_item_t items[11];
        items[0].name = "CTR H2D copy";
        items[0].ns = ocl_stats.ctr_host_to_device_ns;
        items[1].name = "CTR device kernel";
        items[1].ns = ocl_stats.ctr_kernel_device_ns;
        items[2].name = "CTR D2H copy";
        items[2].ns = ocl_stats.ctr_device_to_host_ns;
        items[3].name = "GHASH H2D copy";
        items[3].ns = ocl_stats.ghash_host_to_device_ns;
        items[4].name = "GHASH device copy";
        items[4].ns = ocl_stats.ghash_device_copy_ns;
        items[5].name = "GHASH chunk kernel";
        items[5].ns = ocl_stats.ghash_kernel_device_ns;
        items[6].name = "GHASH reduce kernel";
        items[6].ns = ocl_stats.ghash_reduce_kernel_device_ns;
        items[7].name = "GHASH chunk D2H";
        items[7].ns = ocl_stats.ghash_device_to_host_ns;
        items[8].name = "GHASH final D2H";
        items[8].ns = ocl_stats.ghash_reduce_device_to_host_ns;
        items[9].name = "GHASH CPU reduce";
        items[9].ns = ocl_stats.ghash_cpu_reduce_ns;
        items[10].name = "Round-key upload";
        items[10].ns = ocl_stats.round_key_upload_ns;
        print_ranked_breakdown("Nested OpenCL stages:", total, items, 11);
    }

    print_cpu_helper_hotspots(&cpu_stats, decrypt_mode ? ocl_stats.gcm_decrypt_ns : ocl_stats.gcm_encrypt_ns);
    print_opencl_hints_gcm(&ocl_stats, &cpu_stats, decrypt_mode);
    free(ciphertext);
    return 1;
}

int main(int argc, char** argv)
{
    size_t len = 64u * 1024u * 1024u;
    int iters = 3;
    uint8_t key128[16];
    uint8_t iv[16];
    uint8_t iv12[12];
    uint8_t* input;
    uint8_t* output;

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

    fill_random(key128, sizeof(key128));
    fill_random(iv, sizeof(iv));
    fill_random(iv12, sizeof(iv12));

    input = (uint8_t*)malloc(len);
    output = (uint8_t*)malloc(len);
    if (!input || !output) {
        printf("Allocation failed\n");
        free(input);
        free(output);
        return 1;
    }

    fill_random(input, len);

    printf("OpenCL profiler build active\n");
    printf("Input size: %.2f MiB\n", bytes_to_mib(len));

    if (!run_cold_init_profile(key128, sizeof(key128), iv, input, output, len)) {
        free(input);
        free(output);
        return 2;
    }
    if (!run_warm_ctr_profile(key128, sizeof(key128), iv, input, output, len, iters)) {
        free(input);
        free(output);
        return 3;
    }
    if (!run_warm_gcm_profile(key128, sizeof(key128), iv12, input, output, len, iters, 0)) {
        free(input);
        free(output);
        return 4;
    }
    if (!run_warm_gcm_profile(key128, sizeof(key128), iv12, input, output, len, iters, 1)) {
        free(input);
        free(output);
        return 5;
    }

    crypto_ocl_shutdown();
    free(input);
    free(output);
    return 0;
}
