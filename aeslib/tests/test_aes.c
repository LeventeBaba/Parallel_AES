#include <stdio.h>
#include <string.h>

#include "aes.h"
#include "aes_ctr.h"
#include "aes_gcm.h"
#include "cbc.h"
#include "crypto_ffi.h"

static int buf_eq(const uint8_t* a, const uint8_t* b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

static int test_block_vectors(void)
{
    static const uint8_t pt[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };

    static const uint8_t key128[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    static const uint8_t key192[24] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17
    };

    static const uint8_t key256[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };

    static const uint8_t ct128_expected[16] = {
        0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
    };

    static const uint8_t ct192_expected[16] = {
        0xdd,0xa9,0x7c,0xa4,0x86,0x4c,0xdf,0xe0,0x6e,0xaf,0x70,0xa0,0xec,0x0d,0x71,0x91
    };

    static const uint8_t ct256_expected[16] = {
        0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89
    };

    crypto_aes_t aes;
    uint8_t ct[16];
    uint8_t dt[16];

    if (crypto_aes_init(&aes, key128, sizeof(key128)) != CRYPTO_OK) {
        printf("aes128 init failed\n");
        return 1;
    }
    crypto_aes_encrypt_block(&aes, pt, ct);
    if (!buf_eq(ct, ct128_expected, 16)) {
        printf("aes128 block encrypt test failed\n");
        return 2;
    }
    crypto_aes_decrypt_block(&aes, ct, dt);
    if (!buf_eq(dt, pt, 16)) {
        printf("aes128 block decrypt test failed\n");
        return 3;
    }
    crypto_aes_clear(&aes);

    if (crypto_aes_init(&aes, key192, sizeof(key192)) != CRYPTO_OK) {
        printf("aes192 init failed\n");
        return 4;
    }
    crypto_aes_encrypt_block(&aes, pt, ct);
    if (!buf_eq(ct, ct192_expected, 16)) {
        printf("aes192 block encrypt test failed\n");
        return 5;
    }
    crypto_aes_decrypt_block(&aes, ct, dt);
    if (!buf_eq(dt, pt, 16)) {
        printf("aes192 block decrypt test failed\n");
        return 6;
    }
    crypto_aes_clear(&aes);

    if (crypto_aes_init(&aes, key256, sizeof(key256)) != CRYPTO_OK) {
        printf("aes256 init failed\n");
        return 7;
    }
    crypto_aes_encrypt_block(&aes, pt, ct);
    if (!buf_eq(ct, ct256_expected, 16)) {
        printf("aes256 block encrypt test failed\n");
        return 8;
    }
    crypto_aes_decrypt_block(&aes, ct, dt);
    if (!buf_eq(dt, pt, 16)) {
        printf("aes256 block decrypt test failed\n");
        return 9;
    }
    crypto_aes_clear(&aes);

    return 0;
}

static int test_ctr_vectors(void)
{
    static const uint8_t iv[16] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
    };

    static const uint8_t pt[64] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
        0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
        0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10
    };

    static const uint8_t key128[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };

    static const uint8_t ct128_expected[64] = {
        0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce,
        0x98,0x06,0xf6,0x6b,0x79,0x70,0xfd,0xff,0x86,0x17,0x18,0x7b,0xb9,0xff,0xfd,0xff,
        0x5a,0xe4,0xdf,0x3e,0xdb,0xd5,0xd3,0x5e,0x5b,0x4f,0x09,0x02,0x0d,0xb0,0x3e,0xab,
        0x1e,0x03,0x1d,0xda,0x2f,0xbe,0x03,0xd1,0x79,0x21,0x70,0xa0,0xf3,0x00,0x9c,0xee
    };

    static const uint8_t key192[24] = {
        0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
        0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b
    };

    static const uint8_t ct192_expected[64] = {
        0x1a,0xbc,0x93,0x24,0x17,0x52,0x1c,0xa2,0x4f,0x2b,0x04,0x59,0xfe,0x7e,0x6e,0x0b,
        0x09,0x03,0x39,0xec,0x0a,0xa6,0xfa,0xef,0xd5,0xcc,0xc2,0xc6,0xf4,0xce,0x8e,0x94,
        0x1e,0x36,0xb2,0x6b,0xd1,0xeb,0xc6,0x70,0xd1,0xbd,0x1d,0x66,0x56,0x20,0xab,0xf7,
        0x4f,0x78,0xa7,0xf6,0xd2,0x98,0x09,0x58,0x5a,0x97,0xda,0xec,0x58,0xc6,0xb0,0x50
    };

    static const uint8_t key256[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };

    static const uint8_t ct256_expected[64] = {
        0x60,0x1e,0xc3,0x13,0x77,0x57,0x89,0xa5,0xb7,0xa7,0xf5,0x04,0xbb,0xf3,0xd2,0x28,
        0xf4,0x43,0xe3,0xca,0x4d,0x62,0xb5,0x9a,0xca,0x84,0xe9,0x90,0xca,0xca,0xf5,0xc5,
        0x2b,0x09,0x30,0xda,0xa2,0x3d,0xe9,0x4c,0xe8,0x70,0x17,0xba,0x2d,0x84,0x98,0x8d,
        0xdf,0xc9,0xc5,0x8d,0xb6,0x7a,0xad,0xa6,0x13,0xc2,0xdd,0x08,0x45,0x79,0x41,0xa6
    };

    uint8_t out[64];

    if (crypto_aes_ctr_xor(key128, sizeof(key128), iv, pt, out, sizeof(pt), 0) != CRYPTO_OK || !buf_eq(out, ct128_expected, sizeof(pt))) {
        printf("aes128 ctr vector failed\n");
        return 1;
    }

    if (crypto_aes_ctr_xor(key192, sizeof(key192), iv, pt, out, sizeof(pt), 0) != CRYPTO_OK || !buf_eq(out, ct192_expected, sizeof(pt))) {
        printf("aes192 ctr vector failed\n");
        return 2;
    }

    if (crypto_aes_ctr_xor(key256, sizeof(key256), iv, pt, out, sizeof(pt), 0) != CRYPTO_OK || !buf_eq(out, ct256_expected, sizeof(pt))) {
        printf("aes256 ctr vector failed\n");
        return 3;
    }

    return 0;
}

static int test_cbc_roundtrip(void)
{
    static const uint8_t iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    static const uint8_t keys[3][32] = {
        { 0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c },
        { 0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b },
        { 0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4 }
    };

    static const size_t key_lens[3] = { 16, 24, 32 };

    uint8_t msg[27];
    uint8_t out[64];
    uint8_t back[64];

    memcpy(msg, "The quick brown fox jumps", 25);
    msg[25] = '!';
    msg[26] = '\n';

    for (int i = 0; i < 3; i++) {
        crypto_aes_t aes;
        crypto_cbc_t cbc;
        size_t out_len;
        size_t back_len;

        if (crypto_aes_init(&aes, keys[i], key_lens[i]) != CRYPTO_OK) {
            printf("cbc aes init failed\n");
            return 1;
        }

        if (crypto_cbc_init(&cbc, crypto_aes_block_cipher(&aes), iv, CRYPTO_PADDING_PKCS7) != CRYPTO_OK) {
            printf("cbc init failed\n");
            crypto_aes_clear(&aes);
            return 2;
        }

        if (crypto_cbc_encrypt_buffer(&cbc, msg, sizeof(msg), out, sizeof(out), &out_len) != CRYPTO_OK) {
            printf("cbc encrypt failed\n");
            crypto_aes_clear(&aes);
            return 3;
        }

        if (crypto_cbc_decrypt_buffer(&cbc, out, out_len, back, sizeof(back), &back_len) != CRYPTO_OK) {
            printf("cbc decrypt failed\n");
            crypto_aes_clear(&aes);
            return 4;
        }

        if (back_len != sizeof(msg) || memcmp(back, msg, sizeof(msg)) != 0) {
            printf("cbc roundtrip failed\n");
            crypto_aes_clear(&aes);
            return 5;
        }

        crypto_aes_clear(&aes);
    }

    return 0;
}

static int test_padding_roundtrips(void)
{
    static const uint8_t iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };

    static const crypto_padding_t paddings[] = {
        CRYPTO_PADDING_PKCS7,
        CRYPTO_PADDING_ANSIX923,
        CRYPTO_PADDING_ISO7816_4,
        CRYPTO_PADDING_ZERO,
        CRYPTO_PADDING_NONE
    };

    static const size_t lens[] = {0, 1, 15, 16, 17, 31, 32, 33};

    for (size_t p = 0; p < sizeof(paddings) / sizeof(paddings[0]); p++) {
        for (size_t i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
            size_t n = lens[i];
            uint8_t msg[64];
            for (size_t j = 0; j < n; j++) {
                msg[j] = (uint8_t)(j + 1);
            }
            if (n) {
                msg[n - 1] = 0x11;
            }

            {
                uint8_t* ct = NULL;
                size_t ct_len = 0;
                uint8_t* back = NULL;
                size_t back_len = 0;
                crypto_status_t st;

                st = crypto_ffi_aes_ctr_encrypt_alloc(key, sizeof(key), iv, paddings[p], msg, n, &ct, &ct_len);

                if (paddings[p] == CRYPTO_PADDING_NONE && (n % 16) != 0) {
                    if (st == CRYPTO_OK) {
                        printf("CTR expected error for NONE padding (len=%llu)\n", (unsigned long long)n);
                        crypto_ffi_free(ct);
                        return 1;
                    }
                    continue;
                }

                if (st != CRYPTO_OK) {
                    printf("CTR encrypt failed (padding=%d len=%llu)\n", (int)paddings[p], (unsigned long long)n);
                    return 2;
                }

                st = crypto_ffi_aes_ctr_decrypt_alloc(key, sizeof(key), iv, paddings[p], ct, ct_len, &back, &back_len);
                if (st != CRYPTO_OK) {
                    printf("CTR decrypt failed (padding=%d len=%llu)\n", (int)paddings[p], (unsigned long long)n);
                    crypto_ffi_free(ct);
                    return 3;
                }

                if (back_len != n || (n && memcmp(back, msg, n) != 0)) {
                    printf("CTR roundtrip mismatch (padding=%d len=%llu)\n", (int)paddings[p], (unsigned long long)n);
                    crypto_ffi_free(ct);
                    crypto_ffi_free(back);
                    return 4;
                }

                crypto_ffi_free(ct);
                crypto_ffi_free(back);
            }

            {
                crypto_aes_t aes;
                crypto_cbc_t cbc;
                uint8_t ct[128];
                uint8_t back[128];
                size_t ct_len = 0;
                size_t back_len = 0;

                crypto_status_t st = crypto_aes_init(&aes, key, sizeof(key));
                if (st != CRYPTO_OK) {
                    printf("CBC AES init failed\n");
                    return 5;
                }

                st = crypto_cbc_init(&cbc, crypto_aes_block_cipher(&aes), iv, paddings[p]);
                if (st != CRYPTO_OK) {
                    crypto_aes_clear(&aes);
                    printf("CBC init failed (padding=%d)\n", (int)paddings[p]);
                    return 6;
                }

                st = crypto_cbc_encrypt_buffer(&cbc, msg, n, ct, sizeof(ct), &ct_len);
                if (paddings[p] == CRYPTO_PADDING_NONE && (n % 16) != 0) {
                    if (st == CRYPTO_OK) {
                        crypto_aes_clear(&aes);
                        printf("CBC expected error for NONE padding (len=%llu)\n", (unsigned long long)n);
                        return 7;
                    }
                    crypto_aes_clear(&aes);
                    continue;
                }

                if (st != CRYPTO_OK) {
                    crypto_aes_clear(&aes);
                    printf("CBC encrypt failed (padding=%d len=%llu)\n", (int)paddings[p], (unsigned long long)n);
                    return 8;
                }

                st = crypto_cbc_decrypt_buffer(&cbc, ct, ct_len, back, sizeof(back), &back_len);
                if (st != CRYPTO_OK) {
                    crypto_aes_clear(&aes);
                    printf("CBC decrypt failed (padding=%d len=%llu)\n", (int)paddings[p], (unsigned long long)n);
                    return 9;
                }

                if (back_len != n || (n && memcmp(back, msg, n) != 0)) {
                    crypto_aes_clear(&aes);
                    printf("CBC roundtrip mismatch (padding=%d len=%llu)\n", (int)paddings[p], (unsigned long long)n);
                    return 10;
                }

                crypto_aes_clear(&aes);
            }
        }
    }

    return 0;
}

static int test_gcm_vectors(void)
{
    static const uint8_t key[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };

    static const uint8_t iv12[12] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };

    {
        uint8_t tag[16];
        uint8_t ct[1];
        static const uint8_t expected_tag[16] = {
            0x58,0xe2,0xfc,0xce,0xfa,0x7e,0x30,0x61,0x36,0x7f,0x1d,0x57,0xa4,0xe7,0x45,0x5a
        };

        if (crypto_aes_gcm_encrypt(key, sizeof(key), iv12, sizeof(iv12), NULL, 0, NULL, 0, ct, tag) != CRYPTO_OK) {
            printf("GCM encrypt (empty) failed\n");
            return 1;
        }

        if (memcmp(tag, expected_tag, 16) != 0) {
            printf("GCM tag mismatch (empty)\n");
            return 2;
        }

        if (crypto_aes_gcm_decrypt(key, sizeof(key), iv12, sizeof(iv12), NULL, 0, ct, 0, tag, ct) != CRYPTO_OK) {
            printf("GCM decrypt (empty) failed\n");
            return 3;
        }
    }

    {
        static const uint8_t pt[16] = {
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        };
        static const uint8_t expected_ct[16] = {
            0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78
        };
        static const uint8_t expected_tag[16] = {
            0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf
        };

        uint8_t ct[16];
        uint8_t tag[16];
        uint8_t back[16];

        if (crypto_aes_gcm_encrypt(key, sizeof(key), iv12, sizeof(iv12), NULL, 0, pt, sizeof(pt), ct, tag) != CRYPTO_OK) {
            printf("GCM encrypt failed\n");
            return 4;
        }

        if (memcmp(ct, expected_ct, 16) != 0 || memcmp(tag, expected_tag, 16) != 0) {
            printf("GCM vector mismatch\n");
            return 5;
        }

        if (crypto_aes_gcm_decrypt(key, sizeof(key), iv12, sizeof(iv12), NULL, 0, ct, sizeof(ct), tag, back) != CRYPTO_OK) {
            printf("GCM decrypt failed\n");
            return 6;
        }

        if (memcmp(back, pt, 16) != 0) {
            printf("GCM roundtrip mismatch\n");
            return 7;
        }

        tag[0] ^= 1;
        if (crypto_aes_gcm_decrypt(key, sizeof(key), iv12, sizeof(iv12), NULL, 0, ct, sizeof(ct), tag, back) != CRYPTO_AUTH_FAILED) {
            printf("GCM auth failure not detected\n");
            return 8;
        }
    }

    {
        uint8_t key2[16];
        uint8_t iv2[12];
        uint8_t aad2[37];
        uint8_t pt2[103];
        uint8_t ct2[103];
        uint8_t tag2[16];
        uint8_t back2[103];

        for (int i = 0; i < 16; i++) {
            key2[i] = (uint8_t)(0x10 + i);
        }
        for (int i = 0; i < 12; i++) {
            iv2[i] = (uint8_t)(0xa0 + i);
        }
        for (int i = 0; i < 37; i++) {
            aad2[i] = (uint8_t)(((unsigned)i * 3u) + 7u);
        }
        for (int i = 0; i < 103; i++) {
            pt2[i] = (uint8_t)(i ^ (i >> 2));
        }

        if (crypto_aes_gcm_encrypt(key2, sizeof(key2), iv2, sizeof(iv2), aad2, sizeof(aad2), pt2, sizeof(pt2), ct2, tag2) != CRYPTO_OK) {
            printf("GCM encrypt (random) failed\n");
            return 9;
        }

        if (crypto_aes_gcm_decrypt(key2, sizeof(key2), iv2, sizeof(iv2), aad2, sizeof(aad2), ct2, sizeof(ct2), tag2, back2) != CRYPTO_OK) {
            printf("GCM decrypt (random) failed\n");
            return 10;
        }

        if (memcmp(back2, pt2, sizeof(pt2)) != 0) {
            printf("GCM roundtrip mismatch (random)\n");
            return 11;
        }
    }

    {
        uint8_t key192[24];
        uint8_t key256[32];
        uint8_t iv2[12];
        uint8_t aad2[37];
        uint8_t pt2[103];
        uint8_t ct2[103];
        uint8_t tag2[16];
        uint8_t back2[103];

        for (int i = 0; i < 24; i++) {
            key192[i] = (uint8_t)(0x20 + i);
        }
        for (int i = 0; i < 32; i++) {
            key256[i] = (uint8_t)(0x30 + i);
        }
        for (int i = 0; i < 12; i++) {
            iv2[i] = (uint8_t)(0xb0 + i);
        }
        for (int i = 0; i < 37; i++) {
            aad2[i] = (uint8_t)(((unsigned)i * 5u) + 1u);
        }
        for (int i = 0; i < 103; i++) {
            pt2[i] = (uint8_t)(i ^ (i >> 1));
        }

        if (crypto_aes_gcm_encrypt(key192, sizeof(key192), iv2, sizeof(iv2), aad2, sizeof(aad2), pt2, sizeof(pt2), ct2, tag2) != CRYPTO_OK) {
            printf("GCM encrypt failed (AES-192)\n");
            return 12;
        }

        if (crypto_aes_gcm_decrypt(key192, sizeof(key192), iv2, sizeof(iv2), aad2, sizeof(aad2), ct2, sizeof(ct2), tag2, back2) != CRYPTO_OK) {
            printf("GCM decrypt failed (AES-192)\n");
            return 13;
        }

        if (memcmp(back2, pt2, sizeof(pt2)) != 0) {
            printf("GCM roundtrip mismatch (AES-192)\n");
            return 14;
        }

        if (crypto_aes_gcm_encrypt(key256, sizeof(key256), iv2, sizeof(iv2), aad2, sizeof(aad2), pt2, sizeof(pt2), ct2, tag2) != CRYPTO_OK) {
            printf("GCM encrypt failed (AES-256)\n");
            return 15;
        }

        if (crypto_aes_gcm_decrypt(key256, sizeof(key256), iv2, sizeof(iv2), aad2, sizeof(aad2), ct2, sizeof(ct2), tag2, back2) != CRYPTO_OK) {
            printf("GCM decrypt failed (AES-256)\n");
            return 16;
        }

        if (memcmp(back2, pt2, sizeof(pt2)) != 0) {
            printf("GCM roundtrip mismatch (AES-256)\n");
            return 17;
        }
    }

    return 0;
}

int main(void)
{
    int r;

    r = test_block_vectors();
    if (r) {
        return r;
    }

    r = test_ctr_vectors();
    if (r) {
        return 20 + r;
    }

    r = test_cbc_roundtrip();
    if (r) {
        return 40 + r;
    }

    r = test_padding_roundtrips();
    if (r) {
        return 60 + r;
    }

    r = test_gcm_vectors();
    if (r) {
        return 80 + r;
    }

    printf("ok\n");
    return 0;
}
