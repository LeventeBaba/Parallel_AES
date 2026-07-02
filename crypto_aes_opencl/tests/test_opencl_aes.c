#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto_ffi.h"
#include "crypto_ffi_opencl.h"

static int is_len_valid_for_padding(size_t len, crypto_padding_t padding)
{
    if (padding == CRYPTO_PADDING_NONE) {
        return (len % 16) == 0;
    }
    return 1;
}

static void fill_bytes(uint8_t* p, size_t n, uint8_t seed)
{
    uint32_t x = (uint32_t)(0x9E3779B9u ^ (uint32_t)seed);
    for (size_t i = 0; i < n; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        p[i] = (uint8_t)x;
    }
}

static int run_ctr_case(size_t key_len, size_t plain_len, crypto_padding_t padding)
{
    uint8_t key[32];
    uint8_t iv[16];
    uint8_t* plain;
    uint8_t* cpu_ct;
    uint8_t* gpu_ct;
    uint8_t* back;
    size_t cpu_ct_len;
    size_t gpu_ct_len;
    size_t back_len;
    crypto_status_t st;

    memset(key, 0, sizeof(key));
    for (size_t i = 0; i < key_len; i++) {
        key[i] = (uint8_t)(i * 3 + 1);
    }
    for (int i = 0; i < 16; i++) {
        iv[i] = (uint8_t)(0xF0u + (uint8_t)i);
    }

    plain = (uint8_t*)malloc(plain_len ? plain_len : 1);
    if (!plain) {
        return 0;
    }
    for (size_t i = 0; i < plain_len; i++) {
        plain[i] = (uint8_t)(i + 1);
    }
    if (plain_len) {
        plain[plain_len - 1] = 0x11;
    }

    cpu_ct = NULL;
    cpu_ct_len = 0;
    st = crypto_ffi_aes_ctr_encrypt_alloc(key, key_len, iv, padding, plain, plain_len, &cpu_ct, &cpu_ct_len);
    if (!is_len_valid_for_padding(plain_len, padding)) {
        if (st == CRYPTO_OK) {
            printf("CPU encrypt expected error (padding=%d plain_len=%llu)\n", (int)padding, (unsigned long long)plain_len);
            crypto_ffi_free(cpu_ct);
            free(plain);
            return 0;
        }
        free(plain);
        return 1;
    }
    if (st != CRYPTO_OK) {
        printf("CPU encrypt failed: %d\n", (int)st);
        free(plain);
        return 0;
    }

    gpu_ct = NULL;
    gpu_ct_len = 0;
    st = crypto_ffi_opencl_aes_ctr_encrypt_alloc(key, key_len, iv, padding, plain, plain_len, &gpu_ct, &gpu_ct_len);
    if (st != CRYPTO_OK) {
        printf("GPU encrypt failed: %d\n", (int)st);
        printf("OpenCL error: %s\n", crypto_ffi_opencl_last_error_message());
        crypto_ffi_free(cpu_ct);
        free(plain);
        return 0;
    }

    if (gpu_ct_len != cpu_ct_len) {
        printf("Length mismatch: gpu=%llu cpu=%llu\n",
               (unsigned long long)gpu_ct_len,
               (unsigned long long)cpu_ct_len);
        crypto_ffi_opencl_free(gpu_ct);
        crypto_ffi_free(cpu_ct);
        free(plain);
        return 0;
    }

    if (memcmp(cpu_ct, gpu_ct, cpu_ct_len) != 0) {
        printf("Ciphertext mismatch (key_len=%llu, plain_len=%llu)\n",
               (unsigned long long)key_len,
               (unsigned long long)plain_len);
        crypto_ffi_opencl_free(gpu_ct);
        crypto_ffi_free(cpu_ct);
        free(plain);
        return 0;
    }

    back = NULL;
    back_len = 0;
    st = crypto_ffi_opencl_aes_ctr_decrypt_alloc(key, key_len, iv, padding, gpu_ct, gpu_ct_len, &back, &back_len);
    if (st != CRYPTO_OK) {
        printf("GPU decrypt failed: %d\n", (int)st);
        printf("OpenCL error: %s\n", crypto_ffi_opencl_last_error_message());
        crypto_ffi_opencl_free(gpu_ct);
        crypto_ffi_free(cpu_ct);
        free(plain);
        return 0;
    }

    if (back_len != plain_len) {
        printf("Plain length mismatch: got=%llu expected=%llu\n",
               (unsigned long long)back_len,
               (unsigned long long)plain_len);
        crypto_ffi_opencl_free(gpu_ct);
        crypto_ffi_opencl_free(back);
        crypto_ffi_free(cpu_ct);
        free(plain);
        return 0;
    }

    if (plain_len && memcmp(plain, back, plain_len) != 0) {
        printf("Roundtrip mismatch (key_len=%llu, plain_len=%llu)\n",
               (unsigned long long)key_len,
               (unsigned long long)plain_len);
        crypto_ffi_opencl_free(gpu_ct);
        crypto_ffi_opencl_free(back);
        crypto_ffi_free(cpu_ct);
        free(plain);
        return 0;
    }

    crypto_ffi_opencl_free(gpu_ct);
    crypto_ffi_opencl_free(back);
    crypto_ffi_free(cpu_ct);
    free(plain);
    return 1;
}

static int run_gcm_case(size_t key_len, size_t iv_len, size_t aad_len, size_t pt_len)
{
    uint8_t key[32];
    uint8_t iv[32];
    uint8_t* aad = NULL;
    uint8_t* pt = NULL;

    uint8_t* cpu_ct = NULL;
    size_t cpu_ct_len = 0;
    uint8_t cpu_tag[16];

    uint8_t* gpu_ct = NULL;
    size_t gpu_ct_len = 0;
    uint8_t gpu_tag[16];

    uint8_t* back = NULL;
    size_t back_len = 0;

    crypto_status_t st;

    memset(key, 0, sizeof(key));
    for (size_t i = 0; i < key_len; i++) {
        key[i] = (uint8_t)(0xA0u + (uint8_t)i);
    }

    memset(iv, 0, sizeof(iv));
    fill_bytes(iv, iv_len, (uint8_t)(0x31u + (uint8_t)iv_len));

    if (aad_len) {
        aad = (uint8_t*)malloc(aad_len);
        if (!aad) {
            return 0;
        }
        fill_bytes(aad, aad_len, (uint8_t)(0x77u + (uint8_t)aad_len));
    }

    if (pt_len) {
        pt = (uint8_t*)malloc(pt_len);
        if (!pt) {
            free(aad);
            return 0;
        }
        fill_bytes(pt, pt_len, (uint8_t)(0x55u + (uint8_t)pt_len));
    }

    st = crypto_ffi_aes_gcm_encrypt_alloc(key, key_len, iv, iv_len, aad, aad_len, pt, pt_len, &cpu_ct, &cpu_ct_len, cpu_tag);
    if (st != CRYPTO_OK) {
        printf("CPU GCM encrypt failed (key_len=%llu iv_len=%llu aad_len=%llu pt_len=%llu): %d\n",
               (unsigned long long)key_len,
               (unsigned long long)iv_len,
               (unsigned long long)aad_len,
               (unsigned long long)pt_len,
               (int)st);
        free(aad);
        free(pt);
        return 0;
    }

    st = crypto_ffi_opencl_aes_gcm_encrypt_alloc(key, key_len, iv, iv_len, aad, aad_len, pt, pt_len, &gpu_ct, &gpu_ct_len, gpu_tag);
    if (st != CRYPTO_OK) {
        printf("GPU GCM encrypt failed (key_len=%llu iv_len=%llu aad_len=%llu pt_len=%llu): %d\n",
               (unsigned long long)key_len,
               (unsigned long long)iv_len,
               (unsigned long long)aad_len,
               (unsigned long long)pt_len,
               (int)st);
        printf("OpenCL error: %s\n", crypto_ffi_opencl_last_error_message());
        crypto_ffi_free(cpu_ct);
        free(aad);
        free(pt);
        return 0;
    }

    if (gpu_ct_len != cpu_ct_len || memcmp(gpu_ct, cpu_ct, cpu_ct_len) != 0 || memcmp(gpu_tag, cpu_tag, 16) != 0) {
        printf("GCM mismatch between CPU and GPU (key_len=%llu iv_len=%llu aad_len=%llu pt_len=%llu)\n",
               (unsigned long long)key_len,
               (unsigned long long)iv_len,
               (unsigned long long)aad_len,
               (unsigned long long)pt_len);
        crypto_ffi_opencl_free(gpu_ct);
        crypto_ffi_free(cpu_ct);
        free(aad);
        free(pt);
        return 0;
    }

    st = crypto_ffi_opencl_aes_gcm_decrypt_alloc(key, key_len, iv, iv_len, aad, aad_len, gpu_ct, gpu_ct_len, gpu_tag, &back, &back_len);
    if (st != CRYPTO_OK) {
        printf("GPU GCM decrypt failed (key_len=%llu iv_len=%llu aad_len=%llu pt_len=%llu): %d\n",
               (unsigned long long)key_len,
               (unsigned long long)iv_len,
               (unsigned long long)aad_len,
               (unsigned long long)pt_len,
               (int)st);
        printf("OpenCL error: %s\n", crypto_ffi_opencl_last_error_message());
        crypto_ffi_opencl_free(gpu_ct);
        crypto_ffi_free(cpu_ct);
        free(aad);
        free(pt);
        return 0;
    }

    if (back_len != pt_len || (pt_len && memcmp(back, pt, pt_len) != 0)) {
        printf("GCM roundtrip mismatch (key_len=%llu iv_len=%llu aad_len=%llu pt_len=%llu)\n",
               (unsigned long long)key_len,
               (unsigned long long)iv_len,
               (unsigned long long)aad_len,
               (unsigned long long)pt_len);
        crypto_ffi_opencl_free(gpu_ct);
        crypto_ffi_opencl_free(back);
        crypto_ffi_free(cpu_ct);
        free(aad);
        free(pt);
        return 0;
    }

    {
        uint8_t bad_tag[16];
        memcpy(bad_tag, gpu_tag, 16);
        bad_tag[0] ^= 0x01;
        uint8_t* tmp = NULL;
        size_t tmp_len = 0;
        crypto_status_t st2 = crypto_ffi_opencl_aes_gcm_decrypt_alloc(key, key_len, iv, iv_len, aad, aad_len, gpu_ct, gpu_ct_len, bad_tag, &tmp, &tmp_len);
        if (tmp) {
            crypto_ffi_opencl_free(tmp);
        }
        if (st2 != CRYPTO_AUTH_FAILED) {
            printf("GCM auth failure test failed (expected %d got %d)\n", (int)CRYPTO_AUTH_FAILED, (int)st2);
            crypto_ffi_opencl_free(gpu_ct);
            crypto_ffi_opencl_free(back);
            crypto_ffi_free(cpu_ct);
            free(aad);
            free(pt);
            return 0;
        }
    }

    crypto_ffi_opencl_free(gpu_ct);
    crypto_ffi_opencl_free(back);
    crypto_ffi_free(cpu_ct);
    free(aad);
    free(pt);
    return 1;
}

static int test_gcm_matrix(void)
{
    size_t key_lens[] = {16, 24, 32};
    size_t iv_lens[] = {12, 16};
    size_t aad_lens[] = {0, 1, 16, 64};
    size_t pt_lens[] = {0, 1, 15, 16, 17, 1024u + 3u};

    for (size_t k = 0; k < sizeof(key_lens) / sizeof(key_lens[0]); k++) {
        for (size_t i = 0; i < sizeof(iv_lens) / sizeof(iv_lens[0]); i++) {
            for (size_t a = 0; a < sizeof(aad_lens) / sizeof(aad_lens[0]); a++) {
                for (size_t p = 0; p < sizeof(pt_lens) / sizeof(pt_lens[0]); p++) {
                    if (!run_gcm_case(key_lens[k], iv_lens[i], aad_lens[a], pt_lens[p])) {
                        return 0;
                    }
                }
            }
        }
    }

    return 1;
}

int main(void)
{
    crypto_status_t st = crypto_ffi_opencl_warmup();
    if (st != CRYPTO_OK) {
        printf("OpenCL warmup failed: %d\n", (int)st);
        printf("OpenCL error: %s\n", crypto_ffi_opencl_last_error_message());
        return 2;
    }

    {
        size_t cases[] = {0, 1, 15, 16, 17, 31, 32, 33, 1024, 1024 * 1024 + 3};
        size_t key_lens[] = {16, 24, 32};
        crypto_padding_t pads[] = {CRYPTO_PADDING_PKCS7, CRYPTO_PADDING_ANSIX923, CRYPTO_PADDING_ISO7816_4, CRYPTO_PADDING_ZERO, CRYPTO_PADDING_NONE};
        int ok = 1;

        for (size_t k = 0; k < sizeof(key_lens) / sizeof(key_lens[0]); k++) {
            for (size_t p = 0; p < sizeof(pads) / sizeof(pads[0]); p++) {
                for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
                    if (!run_ctr_case(key_lens[k], cases[i], pads[p])) {
                        ok = 0;
                        break;
                    }
                }
                if (!ok) {
                    break;
                }
            }
            if (!ok) {
                break;
            }
        }

        if (!ok) {
            printf("TEST FAILED\n");
            return 1;
        }
    }

    if (!test_gcm_matrix()) {
        printf("TEST FAILED\n");
        return 1;
    }

    printf("TEST OK\n");
    return 0;
}
