#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "aes.h"
#include "aes_ctr.h"
#include "aes_gcm.h"
#include "cbc.h"
#include "crypto_padding.h"
#include "crypto_profile.h"
#include "crypto_timer.h"

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
    uint32_t x = 0x12345678u;
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

static void print_ctr_hints(const crypto_profile_stats_t* stats)
{
    uint64_t total = stats->aes_init_ns + stats->aes_ctr_ns;
    if (!total) {
        return;
    }
    printf("Likely bottlenecks:\n");
    if (stats->aes_encrypt_block_ns * 100 >= total * 60) {
        printf("  AES block encryption dominates. The main gains will come from optimizing the round function or vectorizing it.\n");
    }
    if (stats->aes_ctr_xor_ns * 100 >= total * 20) {
        printf("  The XOR loop is visible in the profile. Wider loads and stores may help.\n");
    }
    if (stats->aes_ctr_counter_ns * 100 >= total * 10) {
        printf("  Counter generation is measurable. Reducing per-block overhead may help.\n");
    }
}

static void print_gcm_hints(const crypto_profile_stats_t* stats, int is_decrypt)
{
    uint64_t total = is_decrypt ? stats->aes_gcm_decrypt_ns : stats->aes_gcm_encrypt_ns;
    if (!total) {
        return;
    }
    printf("Likely bottlenecks:\n");
    if (stats->aes_gcm_auth_ns * 100 >= total * 45) {
        printf("  GHASH and tag generation dominate. GF(2^128) multiplication is the first place to optimize or parallelize.\n");
    }
    if (stats->gf128_mul_ns * 100 >= total * 25) {
        printf("  GF128 multiplication is a strong hotspot. A table-based or hardware-assisted path would help the most.\n");
    }
    if (stats->aes_gcm_ctr_ns * 100 >= total * 30) {
        printf("  The CTR keystream path is also expensive. Optimizing AES block throughput will improve GCM too.\n");
    }
}

static void print_cbc_hints(const crypto_profile_stats_t* stats, int is_decrypt)
{
    uint64_t total = stats->aes_init_ns + (is_decrypt ? stats->cbc_decrypt_ns : stats->cbc_encrypt_ns);
    if (!total) {
        return;
    }
    printf("Likely bottlenecks:\n");
    if ((is_decrypt ? stats->aes_decrypt_block_ns : stats->aes_encrypt_block_ns) * 100 >= total * 60) {
        printf("  AES block processing dominates. CBC is serial, so block throughput is the main limit.\n");
    }
    if (!is_decrypt && stats->padding_apply_ns) {
        printf("  Padding overhead is present but usually small compared to AES itself.\n");
    }
    if (is_decrypt && stats->padding_remove_ns) {
        printf("  Padding validation is visible but secondary. The main limit is still serial block processing.\n");
    }
}

static int run_ctr_profile(const uint8_t* key,
                           size_t key_len,
                           const uint8_t iv[16],
                           const uint8_t* input,
                           uint8_t* output,
                           size_t len,
                           int iters)
{
    crypto_profile_stats_t stats;
    uint64_t wall_ns = 0;

    crypto_profile_reset();
    for (int i = 0; i < iters; i++) {
        uint64_t t0 = crypto_time_now_ns();
        crypto_status_t st = crypto_aes_ctr_xor(key, key_len, iv, input, output, len, 0);
        wall_ns += crypto_time_now_ns() - t0;
        if (st != CRYPTO_OK) {
            printf("AES-CTR failed: %d\n", (int)st);
            return 0;
        }
    }
    crypto_profile_get(&stats);

    printf("\n=== CPU AES-CTR profile ===\n");
    printf("Key size: %d-bit\n", (int)(key_len * 8));
    printf("Iterations: %d\n", iters);
    printf("Average wall time: %.3f ms\n", ns_to_ms(wall_ns / (uint64_t)iters));
    printf("Average throughput: %.2f MiB/s\n", throughput_mib_s(len, wall_ns / (uint64_t)iters));

    {
        uint64_t total = stats.aes_init_ns + stats.aes_ctr_ns;
        uint64_t other = total;
        metric_item_t items[5];

        if (other >= stats.aes_init_ns) other -= stats.aes_init_ns; else other = 0;
        if (other >= stats.aes_ctr_counter_ns) other -= stats.aes_ctr_counter_ns; else other = 0;
        if (other >= stats.aes_encrypt_block_ns) other -= stats.aes_encrypt_block_ns; else other = 0;
        if (other >= stats.aes_ctr_xor_ns) other -= stats.aes_ctr_xor_ns; else other = 0;

        items[0].name = "AES key expansion";
        items[0].ns = stats.aes_init_ns;
        items[1].name = "Counter setup";
        items[1].ns = stats.aes_ctr_counter_ns;
        items[2].name = "AES block encrypt";
        items[2].ns = stats.aes_encrypt_block_ns;
        items[3].name = "XOR stream";
        items[3].ns = stats.aes_ctr_xor_ns;
        items[4].name = "Other host overhead";
        items[4].ns = other;

        print_ranked_breakdown("Breakdown:", total, items, 5);
    }

    print_ctr_hints(&stats);
    return 1;
}

static int run_gcm_profile(const uint8_t* key,
                           size_t key_len,
                           const uint8_t iv12[12],
                           const uint8_t* input,
                           uint8_t* output,
                           size_t len,
                           int iters,
                           int decrypt_mode)
{
    crypto_profile_stats_t stats;
    uint64_t wall_ns = 0;
    uint8_t tag[16];
    uint8_t* ciphertext = output;
    uint8_t* plaintext = output;

    if (decrypt_mode) {
        crypto_status_t st = crypto_aes_gcm_encrypt(key, key_len, iv12, 12, NULL, 0, input, len, ciphertext, tag);
        if (st != CRYPTO_OK) {
            printf("AES-GCM setup encrypt failed: %d\n", (int)st);
            return 0;
        }
    }

    crypto_profile_reset();
    for (int i = 0; i < iters; i++) {
        uint64_t t0 = crypto_time_now_ns();
        crypto_status_t st;
        if (decrypt_mode) {
            st = crypto_aes_gcm_decrypt(key, key_len, iv12, 12, NULL, 0, ciphertext, len, tag, plaintext);
        } else {
            st = crypto_aes_gcm_encrypt(key, key_len, iv12, 12, NULL, 0, input, len, ciphertext, tag);
        }
        wall_ns += crypto_time_now_ns() - t0;
        if (st != CRYPTO_OK) {
            printf("AES-GCM %s failed: %d\n", decrypt_mode ? "decrypt" : "encrypt", (int)st);
            return 0;
        }
    }
    crypto_profile_get(&stats);

    printf("\n=== CPU AES-GCM %s profile ===\n", decrypt_mode ? "decrypt" : "encrypt");
    printf("Key size: %d-bit\n", (int)(key_len * 8));
    printf("Iterations: %d\n", iters);
    printf("Average wall time: %.3f ms\n", ns_to_ms(wall_ns / (uint64_t)iters));
    printf("Average throughput: %.2f MiB/s\n", throughput_mib_s(len, wall_ns / (uint64_t)iters));

    {
        uint64_t total = decrypt_mode ? stats.aes_gcm_decrypt_ns : stats.aes_gcm_encrypt_ns;
        uint64_t top_sum = stats.aes_init_ns + stats.aes_gcm_j0_ns + stats.aes_gcm_ctr_ns + stats.aes_gcm_auth_ns;
        uint64_t other = (total >= top_sum) ? (total - top_sum) : 0;
        metric_item_t items[5];

        items[0].name = "AES key expansion";
        items[0].ns = stats.aes_init_ns;
        items[1].name = "J0 preparation";
        items[1].ns = stats.aes_gcm_j0_ns;
        items[2].name = "CTR keystream";
        items[2].ns = stats.aes_gcm_ctr_ns;
        items[3].name = "GHASH and tag path";
        items[3].ns = stats.aes_gcm_auth_ns;
        items[4].name = "Other host overhead";
        items[4].ns = other;

        print_ranked_breakdown("Top-level stages:", total, items, 5);
    }

    {
        uint64_t total = decrypt_mode ? stats.aes_gcm_decrypt_ns : stats.aes_gcm_encrypt_ns;
        metric_item_t hotspots[4];
        hotspots[0].name = "AES block encrypt calls";
        hotspots[0].ns = stats.aes_encrypt_block_ns;
        hotspots[1].name = "GF128 multiply";
        hotspots[1].ns = stats.gf128_mul_ns;
        hotspots[2].name = "GF128 power";
        hotspots[2].ns = stats.gf128_pow_ns;
        hotspots[3].name = "Tag final block";
        hotspots[3].ns = stats.aes_gcm_auth_finalize_ns;
        print_ranked_breakdown("Internal hotspots:", total, hotspots, 4);
    }

    print_gcm_hints(&stats, decrypt_mode);
    return 1;
}

static int run_cbc_profile(const uint8_t* key,
                           size_t key_len,
                           const uint8_t iv[16],
                           const uint8_t* input,
                           uint8_t* ciphertext,
                           uint8_t* plaintext,
                           size_t len,
                           int iters,
                           int decrypt_mode)
{
    crypto_aes_t aes;
    crypto_cbc_t cbc;
    crypto_profile_stats_t stats;
    uint64_t wall_ns = 0;
    size_t ciphertext_len = 0;
    size_t plaintext_len = 0;
    crypto_status_t st;

    st = crypto_aes_init(&aes, key, key_len);
    if (st != CRYPTO_OK) {
        printf("AES init failed: %d\n", (int)st);
        return 0;
    }

    st = crypto_cbc_init(&cbc, crypto_aes_block_cipher(&aes), iv, CRYPTO_PADDING_PKCS7);
    if (st != CRYPTO_OK) {
        printf("CBC init failed: %d\n", (int)st);
        crypto_aes_clear(&aes);
        return 0;
    }

    ciphertext_len = crypto_cbc_ciphertext_size(&cbc, len);
    if (!decrypt_mode) {
        crypto_profile_reset();
        for (int i = 0; i < iters; i++) {
            uint64_t t0 = crypto_time_now_ns();
            st = crypto_cbc_encrypt_buffer(&cbc, input, len, ciphertext, ciphertext_len, &ciphertext_len);
            wall_ns += crypto_time_now_ns() - t0;
            if (st != CRYPTO_OK) {
                printf("CBC encrypt failed: %d\n", (int)st);
                crypto_aes_clear(&aes);
                return 0;
            }
        }
    } else {
        st = crypto_cbc_encrypt_buffer(&cbc, input, len, ciphertext, ciphertext_len, &ciphertext_len);
        if (st != CRYPTO_OK) {
            printf("CBC setup encrypt failed: %d\n", (int)st);
            crypto_aes_clear(&aes);
            return 0;
        }
        crypto_profile_reset();
        for (int i = 0; i < iters; i++) {
            uint64_t t0 = crypto_time_now_ns();
            st = crypto_cbc_decrypt_buffer(&cbc, ciphertext, ciphertext_len, plaintext, ciphertext_len, &plaintext_len);
            wall_ns += crypto_time_now_ns() - t0;
            if (st != CRYPTO_OK) {
                printf("CBC decrypt failed: %d\n", (int)st);
                crypto_aes_clear(&aes);
                return 0;
            }
        }
    }

    crypto_profile_get(&stats);

    printf("\n=== CPU AES-CBC %s profile ===\n", decrypt_mode ? "decrypt" : "encrypt");
    printf("Key size: %d-bit\n", (int)(key_len * 8));
    printf("Iterations: %d\n", iters);
    printf("Average wall time: %.3f ms\n", ns_to_ms(wall_ns / (uint64_t)iters));
    printf("Average throughput: %.2f MiB/s\n", throughput_mib_s(len, wall_ns / (uint64_t)iters));

    {
        uint64_t body = decrypt_mode ? stats.cbc_decrypt_ns : stats.cbc_encrypt_ns;
        uint64_t total = stats.aes_init_ns + body;
        uint64_t block_ns = decrypt_mode ? stats.aes_decrypt_block_ns : stats.aes_encrypt_block_ns;
        uint64_t pad_ns = decrypt_mode ? stats.padding_remove_ns : stats.padding_apply_ns;
        uint64_t other = total;
        metric_item_t items[4];

        if (other >= stats.aes_init_ns) other -= stats.aes_init_ns; else other = 0;
        if (other >= block_ns) other -= block_ns; else other = 0;
        if (other >= pad_ns) other -= pad_ns; else other = 0;

        items[0].name = "AES key expansion";
        items[0].ns = stats.aes_init_ns;
        items[1].name = decrypt_mode ? "AES decrypt blocks" : "AES encrypt blocks";
        items[1].ns = block_ns;
        items[2].name = decrypt_mode ? "Padding removal" : "Padding apply";
        items[2].ns = pad_ns;
        items[3].name = "Other host overhead";
        items[3].ns = other;

        print_ranked_breakdown("Breakdown:", total, items, 4);
    }

    print_cbc_hints(&stats, decrypt_mode);
    crypto_aes_clear(&aes);
    return 1;
}

int main(int argc, char** argv)
{
    size_t len = 64u * 1024u * 1024u;
    int iters = 3;
    uint8_t iv[16];
    uint8_t iv12[12];
    uint8_t key128[16];
    uint8_t* input;
    uint8_t* output1;
    uint8_t* output2;
    size_t cbc_capacity;

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

    fill_random(iv, sizeof(iv));
    fill_random(iv12, sizeof(iv12));
    fill_random(key128, sizeof(key128));

    input = (uint8_t*)malloc(len);
    output1 = (uint8_t*)malloc(len + 16u);
    output2 = (uint8_t*)malloc(len + 16u);
    if (!input || !output1 || !output2) {
        printf("Allocation failed\n");
        free(input);
        free(output1);
        free(output2);
        return 1;
    }

    fill_random(input, len);
    cbc_capacity = ((len + 15u) / 16u) * 16u + 16u;

    printf("CPU profiler build active\n");
    printf("Input size: %.2f MiB\n", bytes_to_mib(len));

    if (!run_ctr_profile(key128, sizeof(key128), iv, input, output1, len, iters)) {
        free(input);
        free(output1);
        free(output2);
        return 2;
    }
    if (!run_gcm_profile(key128, sizeof(key128), iv12, input, output1, len, iters, 0)) {
        free(input);
        free(output1);
        free(output2);
        return 3;
    }
    if (!run_gcm_profile(key128, sizeof(key128), iv12, input, output1, len, iters, 1)) {
        free(input);
        free(output1);
        free(output2);
        return 4;
    }
    if (!run_cbc_profile(key128, sizeof(key128), iv, input, output1, output2, len, iters, 0)) {
        free(input);
        free(output1);
        free(output2);
        return 5;
    }
    if (!run_cbc_profile(key128, sizeof(key128), iv, input, output1, output2, len, iters, 1)) {
        free(input);
        free(output1);
        free(output2);
        return 6;
    }

    free(input);
    free(output1);
    free(output2);
    (void)cbc_capacity;
    return 0;
}
