#include "cbc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef CRYPTO_PROFILE
#include "crypto_timer.h"
#include "crypto_profile.h"
#endif

static void secure_zero(void* p, size_t n)
{
    volatile uint8_t* v = (volatile uint8_t*)p;
    while (n--) {
        *v++ = 0;
    }
}



crypto_status_t crypto_cbc_init(crypto_cbc_t* cbc, crypto_block_cipher_t cipher, const uint8_t iv16[16], crypto_padding_t padding)
{
    if (!cbc || !cipher.vtable || !cipher.ctx || !iv16) {
        return CRYPTO_INVALID_ARG;
    }
    if (cipher.vtable->block_size != 16) {
        return CRYPTO_UNSUPPORTED;
    }
    if (!crypto_padding_supported(padding)) {
        return CRYPTO_UNSUPPORTED;
    }

    cbc->cipher = cipher;
    cbc->padding = padding;
    memcpy(cbc->iv, iv16, 16);

    return CRYPTO_OK;
}

size_t crypto_cbc_ciphertext_size(const crypto_cbc_t* cbc, size_t plaintext_len)
{
    size_t out_len = 0;
    if (!cbc) {
        return 0;
    }
    if (crypto_padding_padded_size(plaintext_len, cbc->padding, &out_len) != CRYPTO_OK) {
        return 0;
    }
    return out_len;
}

crypto_status_t crypto_cbc_encrypt_buffer(const crypto_cbc_t* cbc,
                                         const uint8_t* plaintext,
                                         size_t plaintext_len,
                                         uint8_t* ciphertext,
                                         size_t ciphertext_capacity,
                                         size_t* ciphertext_len_out)
{
#ifdef CRYPTO_PROFILE
    uint64_t t0 = crypto_time_now_ns();
#endif
    size_t out_len;
    uint8_t prev[16];
    uint8_t block[16];
    size_t full_blocks;
    size_t rem;
    size_t i;

    if (!cbc || !plaintext || !ciphertext || !ciphertext_len_out) {
        return CRYPTO_INVALID_ARG;
    }

    if (!cbc->cipher.vtable || !cbc->cipher.vtable->encrypt_block || cbc->cipher.vtable->block_size != 16) {
        return CRYPTO_INVALID_ARG;
    }

    if (!crypto_padding_supported(cbc->padding)) {
        return CRYPTO_UNSUPPORTED;
    }

    {
        crypto_status_t st2 = crypto_padding_padded_size(plaintext_len, cbc->padding, &out_len);
        if (st2 != CRYPTO_OK) {
            return st2;
        }
    }
    if (ciphertext_capacity < out_len) {
        return CRYPTO_BUFFER_TOO_SMALL;
    }

    memcpy(prev, cbc->iv, 16);

    full_blocks = plaintext_len / 16;
    rem = plaintext_len % 16;

    for (i = 0; i < full_blocks; i++) {
        size_t j;
        const uint8_t* in = plaintext + (i * 16);
        for (j = 0; j < 16; j++) {
            block[j] = (uint8_t)(in[j] ^ prev[j]);
        }
        cbc->cipher.vtable->encrypt_block(cbc->cipher.ctx, block, ciphertext + (i * 16));
        memcpy(prev, ciphertext + (i * 16), 16);
    }

    if (out_len > plaintext_len) {
        crypto_padding_apply_block(block, rem ? (plaintext + (full_blocks * 16)) : NULL, rem, cbc->padding);
        {
            size_t j;
            for (j = 0; j < 16; j++) {
                block[j] ^= prev[j];
            }
        }
        cbc->cipher.vtable->encrypt_block(cbc->cipher.ctx, block, ciphertext + (full_blocks * 16));
    }

    *ciphertext_len_out = out_len;

    secure_zero(prev, sizeof(prev));
    secure_zero(block, sizeof(block));

#ifdef CRYPTO_PROFILE
    crypto_profile_add_cbc_encrypt(crypto_time_now_ns() - t0, plaintext_len);
#endif

    return CRYPTO_OK;
}

crypto_status_t crypto_cbc_decrypt_buffer(const crypto_cbc_t* cbc,
                                         const uint8_t* ciphertext,
                                         size_t ciphertext_len,
                                         uint8_t* plaintext,
                                         size_t plaintext_capacity,
                                         size_t* plaintext_len_out)
{
#ifdef CRYPTO_PROFILE
    uint64_t t0 = crypto_time_now_ns();
#endif
    uint8_t prev[16];
    uint8_t block[16];
    size_t blocks;
    size_t i;
    size_t tmp_len;
    crypto_status_t st;

    if (!cbc || !ciphertext || !plaintext || !plaintext_len_out) {
        return CRYPTO_INVALID_ARG;
    }

    if (!cbc->cipher.vtable || !cbc->cipher.vtable->decrypt_block || cbc->cipher.vtable->block_size != 16) {
        return CRYPTO_INVALID_ARG;
    }

    if (!crypto_padding_supported(cbc->padding)) {
        return CRYPTO_UNSUPPORTED;
    }

    if (ciphertext_len == 0) {
        if (cbc->padding == CRYPTO_PADDING_ZERO || cbc->padding == CRYPTO_PADDING_NONE) {
            *plaintext_len_out = 0;
            return CRYPTO_OK;
        }
        return CRYPTO_BAD_PADDING;
    }

    if ((ciphertext_len % 16) != 0) {
        return CRYPTO_INVALID_ARG;
    }

    if (plaintext_capacity < ciphertext_len) {
        return CRYPTO_BUFFER_TOO_SMALL;
    }

    memcpy(prev, cbc->iv, 16);

    blocks = ciphertext_len / 16;
    for (i = 0; i < blocks; i++) {
        const uint8_t* in = ciphertext + (i * 16);
        size_t j;

        cbc->cipher.vtable->decrypt_block(cbc->cipher.ctx, in, block);
        for (j = 0; j < 16; j++) {
            plaintext[i * 16 + j] = (uint8_t)(block[j] ^ prev[j]);
        }
        memcpy(prev, in, 16);
    }

    st = crypto_padding_remove(plaintext, ciphertext_len, cbc->padding, &tmp_len);
    if (st != CRYPTO_OK) {
        secure_zero(prev, sizeof(prev));
        secure_zero(block, sizeof(block));
        return st;
    }

    *plaintext_len_out = tmp_len;

    secure_zero(prev, sizeof(prev));
    secure_zero(block, sizeof(block));

#ifdef CRYPTO_PROFILE
    crypto_profile_add_cbc_decrypt(crypto_time_now_ns() - t0, ciphertext_len);
#endif

    return CRYPTO_OK;
}

crypto_status_t crypto_cbc_encrypt_alloc(const crypto_cbc_t* cbc,
                                        const uint8_t* plaintext,
                                        size_t plaintext_len,
                                        uint8_t** ciphertext_out,
                                        size_t* ciphertext_len_out)
{
    size_t out_len;
    uint8_t* out;
    crypto_status_t st;

    if (!ciphertext_out || !ciphertext_len_out) {
        return CRYPTO_INVALID_ARG;
    }

    out_len = crypto_cbc_ciphertext_size(cbc, plaintext_len);
    out = (uint8_t*)malloc(out_len);
    if (!out) {
        return CRYPTO_INTERNAL_ERROR;
    }

    st = crypto_cbc_encrypt_buffer(cbc, plaintext, plaintext_len, out, out_len, ciphertext_len_out);
    if (st != CRYPTO_OK) {
        secure_zero(out, out_len);
        free(out);
        return st;
    }

    *ciphertext_out = out;
    return CRYPTO_OK;
}

crypto_status_t crypto_cbc_decrypt_alloc(const crypto_cbc_t* cbc,
                                        const uint8_t* ciphertext,
                                        size_t ciphertext_len,
                                        uint8_t** plaintext_out,
                                        size_t* plaintext_len_out)
{
    uint8_t* out;
    crypto_status_t st;

    if (!cbc || !ciphertext || !plaintext_out || !plaintext_len_out) {
        return CRYPTO_INVALID_ARG;
    }

    out = (uint8_t*)malloc(ciphertext_len);
    if (!out) {
        return CRYPTO_INTERNAL_ERROR;
    }

    st = crypto_cbc_decrypt_buffer(cbc, ciphertext, ciphertext_len, out, ciphertext_len, plaintext_len_out);
    if (st != CRYPTO_OK) {
        secure_zero(out, ciphertext_len);
        free(out);
        return st;
    }

    *plaintext_out = out;
    return CRYPTO_OK;
}

static crypto_status_t file_write_all(FILE* f, const uint8_t* buf, size_t n)
{
    if (n == 0) {
        return CRYPTO_OK;
    }
    if (fwrite(buf, 1, n, f) != n) {
        return CRYPTO_IO_ERROR;
    }
    return CRYPTO_OK;
}

static crypto_status_t file_read_exact(FILE* f, uint8_t* buf, size_t n)
{
    size_t r = fread(buf, 1, n, f);
    if (r != n) {
        if (feof(f)) {
            return CRYPTO_IO_ERROR;
        }
        return CRYPTO_IO_ERROR;
    }
    return CRYPTO_OK;
}

crypto_status_t crypto_cbc_encrypt_file(const crypto_cbc_t* cbc,
                                       const char* input_path,
                                       const char* output_path,
                                       int prefix_iv)
{
    FILE* in;
    FILE* out;
    uint8_t prev[16];
    uint8_t inbuf[65536];
    uint8_t carry[16];
    size_t carry_len = 0;
    crypto_status_t st = CRYPTO_OK;

    if (!cbc || !input_path || !output_path) {
        return CRYPTO_INVALID_ARG;
    }

    in = fopen(input_path, "rb");
    if (!in) {
        return CRYPTO_IO_ERROR;
    }

    out = fopen(output_path, "wb");
    if (!out) {
        fclose(in);
        return CRYPTO_IO_ERROR;
    }

    memcpy(prev, cbc->iv, 16);

    if (prefix_iv) {
        st = file_write_all(out, cbc->iv, 16);
        if (st != CRYPTO_OK) {
            fclose(in);
            fclose(out);
            return st;
        }
    }

    while (1) {
        size_t n = fread(inbuf, 1, sizeof(inbuf), in);
        size_t total;
        size_t blocks;
        size_t rem;
        size_t i;

        if (n == 0) {
            if (ferror(in)) {
                st = CRYPTO_IO_ERROR;
            }
            break;
        }

        total = carry_len + n;
        blocks = total / 16;
        rem = total % 16;

        for (i = 0; i < blocks; i++) {
            uint8_t block[16];
            size_t j;
            size_t src_off = i * 16;

            for (j = 0; j < 16; j++) {
                uint8_t b;
                if (src_off + j < carry_len) {
                    b = carry[src_off + j];
                } else {
                    b = inbuf[src_off + j - carry_len];
                }
                block[j] = (uint8_t)(b ^ prev[j]);
            }

            cbc->cipher.vtable->encrypt_block(cbc->cipher.ctx, block, block);
            st = file_write_all(out, block, 16);
            if (st != CRYPTO_OK) {
                secure_zero(block, sizeof(block));
                goto cleanup;
            }

            memcpy(prev, block, 16);
            secure_zero(block, sizeof(block));
        }

        if (rem) {
            size_t k;
            for (k = 0; k < rem; k++) {
                size_t src = blocks * 16 + k;
                if (src < carry_len) {
                    carry[k] = carry[src];
                } else {
                    carry[k] = inbuf[src - carry_len];
                }
            }
        }
        carry_len = rem;

        if (n < sizeof(inbuf)) {
            if (feof(in)) {
                break;
            }
            if (ferror(in)) {
                st = CRYPTO_IO_ERROR;
                break;
            }
        }
    }

    if (st == CRYPTO_OK) {
        if (cbc->padding == CRYPTO_PADDING_NONE && carry_len != 0) {
            st = CRYPTO_INVALID_ARG;
        } else if (cbc->padding == CRYPTO_PADDING_ZERO && carry_len == 0) {
            st = CRYPTO_OK;
        } else if (cbc->padding == CRYPTO_PADDING_NONE && carry_len == 0) {
            st = CRYPTO_OK;
        } else {
            uint8_t last[16];
            uint8_t x[16];
            size_t j;

            crypto_padding_apply_block(last, carry_len ? carry : NULL, carry_len, cbc->padding);

            for (j = 0; j < 16; j++) {
                x[j] = (uint8_t)(last[j] ^ prev[j]);
            }

            cbc->cipher.vtable->encrypt_block(cbc->cipher.ctx, x, x);
            st = file_write_all(out, x, 16);

            secure_zero(last, sizeof(last));
            secure_zero(x, sizeof(x));
        }
    }

cleanup:
    secure_zero(prev, sizeof(prev));
    secure_zero(inbuf, sizeof(inbuf));
    secure_zero(carry, sizeof(carry));

    fclose(in);
    fclose(out);

    return st;
}

crypto_status_t crypto_cbc_decrypt_file(const crypto_cbc_t* cbc,
                                       const char* input_path,
                                       const char* output_path,
                                       int prefix_iv)
{
    FILE* in;
    FILE* out;
    uint8_t iv[16];
    uint8_t prev[16];
    uint8_t cblock[16];
    uint8_t pblock[16];
    uint8_t last_plain[16];
    int have_last = 0;
    crypto_status_t st = CRYPTO_OK;

    if (!cbc || !input_path || !output_path) {
        return CRYPTO_INVALID_ARG;
    }

    in = fopen(input_path, "rb");
    if (!in) {
        return CRYPTO_IO_ERROR;
    }

    out = fopen(output_path, "wb");
    if (!out) {
        fclose(in);
        return CRYPTO_IO_ERROR;
    }

    if (prefix_iv) {
        st = file_read_exact(in, iv, 16);
        if (st != CRYPTO_OK) {
            fclose(in);
            fclose(out);
            return st;
        }
    } else {
        memcpy(iv, cbc->iv, 16);
    }

    memcpy(prev, iv, 16);

    while (1) {
        size_t n = fread(cblock, 1, 16, in);
        size_t j;

        if (n == 0) {
            if (ferror(in)) {
                st = CRYPTO_IO_ERROR;
            }
            break;
        }
        if (n != 16) {
            st = CRYPTO_IO_ERROR;
            break;
        }

        cbc->cipher.vtable->decrypt_block(cbc->cipher.ctx, cblock, pblock);
        for (j = 0; j < 16; j++) {
            pblock[j] = (uint8_t)(pblock[j] ^ prev[j]);
        }

        if (have_last) {
            st = file_write_all(out, last_plain, 16);
            if (st != CRYPTO_OK) {
                break;
            }
        }

        memcpy(last_plain, pblock, 16);
        have_last = 1;

        memcpy(prev, cblock, 16);

        if (feof(in)) {
            break;
        }
    }

    if (st == CRYPTO_OK) {
        if (!have_last) {
            st = CRYPTO_BAD_PADDING;
        } else {
            size_t out_len;
            uint8_t tmp[16];
            memcpy(tmp, last_plain, 16);
            st = crypto_padding_remove(tmp, 16, cbc->padding, &out_len);
            if (st == CRYPTO_OK) {
                st = file_write_all(out, tmp, out_len);
            }
            secure_zero(tmp, sizeof(tmp));
        }
    }

    secure_zero(iv, sizeof(iv));
    secure_zero(prev, sizeof(prev));
    secure_zero(cblock, sizeof(cblock));
    secure_zero(pblock, sizeof(pblock));
    secure_zero(last_plain, sizeof(last_plain));

    fclose(in);
    fclose(out);

    return st;
}
