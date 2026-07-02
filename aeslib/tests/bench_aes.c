#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "aes.h"
#include "aes_ctr.h"
#include "aes_gcm.h"
#include "crypto_timer.h"

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

static double ns_to_s(uint64_t ns)
{
    return (double)ns / 1000000000.0;
}

static void print_throughput(const char* label, size_t bytes, uint64_t ns)
{
    double s = ns_to_s(ns);
    double mib = (double)bytes / (1024.0 * 1024.0);
    double mib_s = (s > 0.0) ? (mib / s) : 0.0;
    printf("%s: %.3f ms (%.2f MiB/s)\n", label, s * 1000.0, mib_s);
}

static uint64_t bench_ctr(const uint8_t* key, size_t key_len, const uint8_t iv[16], const uint8_t* in, uint8_t* out, size_t bytes)
{
    crypto_aes_t aes;
    uint64_t best = 0;

    if (crypto_aes_init(&aes, key, key_len) != CRYPTO_OK) {
        return 0;
    }

    for (int r = 0; r < 5; r++) {
        uint64_t t0 = crypto_time_now_ns();
        crypto_status_t st = crypto_aes_ctr_xor_aes(&aes, iv, in, out, bytes, 0);
        uint64_t dt = crypto_time_now_ns() - t0;
        if (st != CRYPTO_OK) {
            crypto_aes_clear(&aes);
            return 0;
        }
        if (best == 0 || dt < best) {
            best = dt;
        }
    }

    crypto_aes_clear(&aes);
    return best;
}

static uint64_t bench_block_encrypt(const uint8_t* key, size_t key_len, const uint8_t* in, uint8_t* out, size_t bytes)
{
    crypto_aes_t aes;
    uint64_t best = 0;

    if (crypto_aes_init(&aes, key, key_len) != CRYPTO_OK) {
        return 0;
    }

    for (int r = 0; r < 5; r++) {
        uint64_t t0 = crypto_time_now_ns();
        for (size_t i = 0; i < bytes; i += 16) {
            crypto_aes_encrypt_block(&aes, in + i, out + i);
        }
        uint64_t dt = crypto_time_now_ns() - t0;
        if (best == 0 || dt < best) {
            best = dt;
        }
    }

    crypto_aes_clear(&aes);
    return best;
}

static uint64_t bench_gcm(const uint8_t* key,
                          size_t key_len,
                          const uint8_t* iv12,
                          const uint8_t* in,
                          uint8_t* out,
                          size_t bytes)
{
    uint64_t best = 0;
    uint8_t tag[16];

    for (int r = 0; r < 3; r++) {
        uint64_t t0 = crypto_time_now_ns();
        crypto_status_t st = crypto_aes_gcm_encrypt(key, key_len, iv12, 12, NULL, 0, in, bytes, out, tag);
        uint64_t dt = crypto_time_now_ns() - t0;
        if (st != CRYPTO_OK) {
            return 0;
        }
        if (best == 0 || dt < best) {
            best = dt;
        }
    }

    return best;
}

int main(void)
{
    const size_t data_size = 256u * 1024u * 1024u;

    uint8_t* in = (uint8_t*)malloc(data_size);
    uint8_t* out = (uint8_t*)malloc(data_size);

    uint8_t iv[16] = {0};

    uint8_t key128[16];
    uint8_t key192[24];
    uint8_t key256[32];

    if (!in || !out) {
        printf("alloc failed\n");
        free(in);
        free(out);
        return 1;
    }

    fill_random(in, data_size);
    fill_random(key128, sizeof(key128));
    fill_random(key192, sizeof(key192));
    fill_random(key256, sizeof(key256));
    fill_random(iv, sizeof(iv));

    printf("Data: %.2f MiB\n", (double)data_size / (1024.0 * 1024.0));

    {
        uint64_t dt = bench_ctr(key128, sizeof(key128), iv, in, out, data_size);
        if (!dt) {
            printf("AES-128 CTR bench failed\n");
            return 2;
        }
        print_throughput("AES-128 CTR", data_size, dt);
    }

    {
        uint64_t dt = bench_ctr(key192, sizeof(key192), iv, in, out, data_size);
        if (!dt) {
            printf("AES-192 CTR bench failed\n");
            return 3;
        }
        print_throughput("AES-192 CTR", data_size, dt);
    }

    {
        uint64_t dt = bench_ctr(key256, sizeof(key256), iv, in, out, data_size);
        if (!dt) {
            printf("AES-256 CTR bench failed\n");
            return 4;
        }
        print_throughput("AES-256 CTR", data_size, dt);
    }

    {
        uint64_t dt = bench_block_encrypt(key128, sizeof(key128), in, out, data_size);
        if (!dt) {
            printf("AES-128 block bench failed\n");
            return 5;
        }
        print_throughput("AES-128 block encrypt", data_size, dt);
    }

    {
        uint64_t dt = bench_block_encrypt(key192, sizeof(key192), in, out, data_size);
        if (!dt) {
            printf("AES-192 block bench failed\n");
            return 6;
        }
        print_throughput("AES-192 block encrypt", data_size, dt);
    }

    {
        uint64_t dt = bench_block_encrypt(key256, sizeof(key256), in, out, data_size);
        if (!dt) {
            printf("AES-256 block bench failed\n");
            return 7;
        }
        print_throughput("AES-256 block encrypt", data_size, dt);
    }

    {
        uint8_t iv12[12];
        fill_random(iv12, sizeof(iv12));

        uint64_t dt = bench_gcm(key128, sizeof(key128), iv12, in, out, data_size);
        if (!dt) {
            printf("AES-128 GCM bench failed\n");
            return 8;
        }
        print_throughput("AES-128 GCM", data_size, dt);

        dt = bench_gcm(key192, sizeof(key192), iv12, in, out, data_size);
        if (!dt) {
            printf("AES-192 GCM bench failed\n");
            return 9;
        }
        print_throughput("AES-192 GCM", data_size, dt);

        dt = bench_gcm(key256, sizeof(key256), iv12, in, out, data_size);
        if (!dt) {
            printf("AES-256 GCM bench failed\n");
            return 10;
        }
        print_throughput("AES-256 GCM", data_size, dt);
    }

    free(in);
    free(out);
    return 0;
}
