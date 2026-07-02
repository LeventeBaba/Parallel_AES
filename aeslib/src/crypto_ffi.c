#include "crypto_ffi.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "aes.h"
#include "aes_ctr.h"
#include "crypto_ctr_stream.h"
#include "crypto_gcm_stream.h"
#include "crypto_padding.h"

static void secure_zero(void* p, size_t n)
{
    volatile uint8_t* v = (volatile uint8_t*)p;
    while (n--) {
        *v++ = 0;
    }
}

static crypto_status_t parse_chunk_size(size_t* out_bytes)
{
    const char* env = getenv("CRYPTO_CTR_CHUNK_BYTES");
    const char* env_compat = getenv("CRYPTO_OCL_CHUNK_BYTES");
    size_t v;

    if (!out_bytes) {
        return CRYPTO_INVALID_ARG;
    }

    v = 64u * 1024u * 1024u;
    if (env && env[0]) {
        unsigned long long tmp = strtoull(env, NULL, 10);
        if (tmp > 0) {
            v = (size_t)tmp;
        }
    } else if (env_compat && env_compat[0]) {
        unsigned long long tmp = strtoull(env_compat, NULL, 10);
        if (tmp > 0) {
            v = (size_t)tmp;
        }
    }

    if (v < 4096) {
        v = 4096;
    }

    if (v % 16 != 0) {
        v = (v / 16) * 16;
        if (v == 0) {
            v = 16;
        }
    }

    *out_bytes = v;
    return CRYPTO_OK;
}

static crypto_status_t aes_key_init(crypto_aes_t* aes, const uint8_t* key, size_t key_len_bytes)
{
    crypto_status_t st;
    st = crypto_aes_init(aes, key, key_len_bytes);
    if (st != CRYPTO_OK) {
        crypto_aes_clear(aes);
    }
    return st;
}

crypto_status_t crypto_ffi_aes_cbc_encrypt_alloc(const uint8_t* key,
                                                size_t key_len_bytes,
                                                const uint8_t iv16[16],
                                                crypto_padding_t padding,
                                                const uint8_t* plaintext,
                                                size_t plaintext_len,
                                                uint8_t** ciphertext_out,
                                                size_t* ciphertext_len_out)
{
    crypto_aes_t aes;
    crypto_cbc_t cbc;
    crypto_status_t st;

    if (!key || !iv16) {
        return CRYPTO_INVALID_ARG;
    }

    st = aes_key_init(&aes, key, key_len_bytes);
    if (st != CRYPTO_OK) {
        return st;
    }

    st = crypto_cbc_init(&cbc, crypto_aes_block_cipher(&aes), iv16, padding);
    if (st != CRYPTO_OK) {
        crypto_aes_clear(&aes);
        return st;
    }

    st = crypto_cbc_encrypt_alloc(&cbc, plaintext, plaintext_len, ciphertext_out, ciphertext_len_out);
    crypto_aes_clear(&aes);
    return st;
}

crypto_status_t crypto_ffi_aes_cbc_decrypt_alloc(const uint8_t* key,
                                                size_t key_len_bytes,
                                                const uint8_t iv16[16],
                                                crypto_padding_t padding,
                                                const uint8_t* ciphertext,
                                                size_t ciphertext_len,
                                                uint8_t** plaintext_out,
                                                size_t* plaintext_len_out)
{
    crypto_aes_t aes;
    crypto_cbc_t cbc;
    crypto_status_t st;

    if (!key || !iv16) {
        return CRYPTO_INVALID_ARG;
    }

    st = aes_key_init(&aes, key, key_len_bytes);
    if (st != CRYPTO_OK) {
        return st;
    }

    st = crypto_cbc_init(&cbc, crypto_aes_block_cipher(&aes), iv16, padding);
    if (st != CRYPTO_OK) {
        crypto_aes_clear(&aes);
        return st;
    }

    st = crypto_cbc_decrypt_alloc(&cbc, ciphertext, ciphertext_len, plaintext_out, plaintext_len_out);
    crypto_aes_clear(&aes);
    return st;
}

crypto_status_t crypto_ffi_aes_cbc_encrypt_file(const uint8_t* key,
                                               size_t key_len_bytes,
                                               const uint8_t iv16[16],
                                               crypto_padding_t padding,
                                               const char* input_path,
                                               const char* output_path,
                                               int prefix_iv)
{
    crypto_aes_t aes;
    crypto_cbc_t cbc;
    crypto_status_t st;

    if (!key || !iv16) {
        return CRYPTO_INVALID_ARG;
    }

    st = aes_key_init(&aes, key, key_len_bytes);
    if (st != CRYPTO_OK) {
        return st;
    }

    st = crypto_cbc_init(&cbc, crypto_aes_block_cipher(&aes), iv16, padding);
    if (st != CRYPTO_OK) {
        crypto_aes_clear(&aes);
        return st;
    }

    st = crypto_cbc_encrypt_file(&cbc, input_path, output_path, prefix_iv);
    crypto_aes_clear(&aes);
    return st;
}

crypto_status_t crypto_ffi_aes_cbc_decrypt_file(const uint8_t* key,
                                               size_t key_len_bytes,
                                               const uint8_t iv16[16],
                                               crypto_padding_t padding,
                                               const char* input_path,
                                               const char* output_path,
                                               int prefix_iv)
{
    crypto_aes_t aes;
    crypto_cbc_t cbc;
    crypto_status_t st;

    if (!key || !iv16) {
        return CRYPTO_INVALID_ARG;
    }

    st = aes_key_init(&aes, key, key_len_bytes);
    if (st != CRYPTO_OK) {
        return st;
    }

    st = crypto_cbc_init(&cbc, crypto_aes_block_cipher(&aes), iv16, padding);
    if (st != CRYPTO_OK) {
        crypto_aes_clear(&aes);
        return st;
    }

    st = crypto_cbc_decrypt_file(&cbc, input_path, output_path, prefix_iv);
    crypto_aes_clear(&aes);
    return st;
}

crypto_status_t crypto_ffi_aes_ctr_encrypt_alloc(const uint8_t* key,
                                                size_t key_len_bytes,
                                                const uint8_t iv16[16],
                                                crypto_padding_t padding,
                                                const uint8_t* plaintext,
                                                size_t plaintext_len,
                                                uint8_t** ciphertext_out,
                                                size_t* ciphertext_len_out)
{
    crypto_aes_t aes;
    crypto_status_t st;
    uint8_t* in_tmp;
    uint8_t* out_tmp;
    size_t out_len;
    size_t full_len;
    size_t rem;
    uint8_t block[16];

    if (!key || !iv16 || !ciphertext_out || !ciphertext_len_out) {
        return CRYPTO_INVALID_ARG;
    }

    if (plaintext_len && !plaintext) {
        return CRYPTO_INVALID_ARG;
    }

    if (!crypto_padding_supported(padding)) {
        return CRYPTO_UNSUPPORTED;
    }

    st = crypto_padding_padded_size(plaintext_len, padding, &out_len);
    if (st != CRYPTO_OK) {
        return st;
    }

    in_tmp = (uint8_t*)malloc(out_len ? out_len : 1);
    if (!in_tmp) {
        return CRYPTO_INTERNAL_ERROR;
    }

    out_tmp = (uint8_t*)malloc(out_len ? out_len : 1);
    if (!out_tmp) {
        free(in_tmp);
        return CRYPTO_INTERNAL_ERROR;
    }

    if (out_len) {
        if (plaintext_len) {
            memcpy(in_tmp, plaintext, plaintext_len);
        }
        if (out_len > plaintext_len) {
            full_len = (plaintext_len / 16) * 16;
            rem = plaintext_len - full_len;
            crypto_padding_apply_block(block, rem ? (plaintext + full_len) : NULL, rem, padding);
            memcpy(in_tmp + full_len, block, 16);
        }
    }

    st = aes_key_init(&aes, key, key_len_bytes);
    if (st != CRYPTO_OK) {
        secure_zero(block, sizeof(block));
        secure_zero(in_tmp, out_len);
        secure_zero(out_tmp, out_len);
        free(in_tmp);
        free(out_tmp);
        return st;
    }

    st = crypto_aes_ctr_xor_aes(&aes, iv16, in_tmp, out_tmp, out_len, 0);

    crypto_aes_clear(&aes);
    secure_zero(block, sizeof(block));
    secure_zero(in_tmp, out_len);
    free(in_tmp);

    if (st != CRYPTO_OK) {
        secure_zero(out_tmp, out_len);
        free(out_tmp);
        return st;
    }

    *ciphertext_out = out_tmp;
    *ciphertext_len_out = out_len;
    return CRYPTO_OK;
}

crypto_status_t crypto_ffi_aes_ctr_decrypt_alloc(const uint8_t* key,
                                                size_t key_len_bytes,
                                                const uint8_t iv16[16],
                                                crypto_padding_t padding,
                                                const uint8_t* ciphertext,
                                                size_t ciphertext_len,
                                                uint8_t** plaintext_out,
                                                size_t* plaintext_len_out)
{
    crypto_aes_t aes;
    crypto_status_t st;
    uint8_t* tmp;
    uint8_t* out;
    size_t out_len;

    if (!key || !iv16 || !ciphertext || !plaintext_out || !plaintext_len_out) {
        return CRYPTO_INVALID_ARG;
    }

    if (!crypto_padding_supported(padding)) {
        return CRYPTO_UNSUPPORTED;
    }

    if (ciphertext_len == 0) {
        if (padding == CRYPTO_PADDING_ZERO || padding == CRYPTO_PADDING_NONE) {
            out = (uint8_t*)malloc(1);
            if (!out) {
                return CRYPTO_INTERNAL_ERROR;
            }
            *plaintext_out = out;
            *plaintext_len_out = 0;
            return CRYPTO_OK;
        }
        return CRYPTO_BAD_PADDING;
    }

    if ((ciphertext_len % 16) != 0) {
        return CRYPTO_INVALID_ARG;
    }

    tmp = (uint8_t*)malloc(ciphertext_len ? ciphertext_len : 1);
    if (!tmp) {
        return CRYPTO_INTERNAL_ERROR;
    }

    st = aes_key_init(&aes, key, key_len_bytes);
    if (st != CRYPTO_OK) {
        secure_zero(tmp, ciphertext_len);
        free(tmp);
        return st;
    }

    st = crypto_aes_ctr_xor_aes(&aes, iv16, ciphertext, tmp, ciphertext_len, 0);
    crypto_aes_clear(&aes);
    if (st != CRYPTO_OK) {
        secure_zero(tmp, ciphertext_len);
        free(tmp);
        return st;
    }

    st = crypto_padding_remove(tmp, ciphertext_len, padding, &out_len);
    if (st != CRYPTO_OK) {
        secure_zero(tmp, ciphertext_len);
        free(tmp);
        return st;
    }

    out = (uint8_t*)malloc(out_len ? out_len : 1);
    if (!out) {
        secure_zero(tmp, ciphertext_len);
        free(tmp);
        return CRYPTO_INTERNAL_ERROR;
    }

    if (out_len) {
        memcpy(out, tmp, out_len);
    }

    secure_zero(tmp, ciphertext_len);
    free(tmp);

    *plaintext_out = out;
    *plaintext_len_out = out_len;
    return CRYPTO_OK;
}

static crypto_status_t file_encrypt_internal(const crypto_aes_t* aes,
                                            const uint8_t iv16[16],
                                            crypto_padding_t padding,
                                            FILE* fin,
                                            FILE* fout)
{
    crypto_status_t st;
    size_t chunk;
    uint8_t* in_buf;
    uint8_t* out_buf;
    uint8_t leftover[16];
    size_t leftover_len = 0;
    uint64_t block_offset = 0;

    st = parse_chunk_size(&chunk);
    if (st != CRYPTO_OK) {
        return st;
    }

    in_buf = (uint8_t*)malloc(chunk + 16);
    out_buf = (uint8_t*)malloc(chunk + 16);
    if (!in_buf || !out_buf) {
        free(in_buf);
        free(out_buf);
        return CRYPTO_INTERNAL_ERROR;
    }

    while (1) {
        size_t n = fread(in_buf + 16, 1, chunk, fin);
        size_t total;
        size_t full_len;
        size_t rem;

        if (n == 0) {
            if (ferror(fin)) {
                free(in_buf);
                free(out_buf);
                return CRYPTO_IO_ERROR;
            }
            break;
        }

        memcpy(in_buf, leftover, leftover_len);
        total = leftover_len + n;
        memmove(in_buf + leftover_len, in_buf + 16, n);

        full_len = (total / 16) * 16;
        rem = total - full_len;

        if (full_len) {
            st = crypto_aes_ctr_xor_aes(aes, iv16, in_buf, out_buf, full_len, block_offset);
            if (st != CRYPTO_OK) {
                free(in_buf);
                free(out_buf);
                return st;
            }
            if (fwrite(out_buf, 1, full_len, fout) != full_len) {
                free(in_buf);
                free(out_buf);
                return CRYPTO_IO_ERROR;
            }
            block_offset += (uint64_t)(full_len / 16);
        }

        if (rem) {
            memcpy(leftover, in_buf + full_len, rem);
        }
        leftover_len = rem;
    }

    if (padding == CRYPTO_PADDING_NONE && leftover_len != 0) {
        secure_zero(leftover, sizeof(leftover));
        free(in_buf);
        free(out_buf);
        return CRYPTO_INVALID_ARG;
    }

    if (padding == CRYPTO_PADDING_ZERO && leftover_len == 0) {
        secure_zero(leftover, sizeof(leftover));
        free(in_buf);
        free(out_buf);
        return CRYPTO_OK;
    }

    if (padding == CRYPTO_PADDING_NONE && leftover_len == 0) {
        secure_zero(leftover, sizeof(leftover));
        free(in_buf);
        free(out_buf);
        return CRYPTO_OK;
    }

    {
        uint8_t final_block[16];
        uint8_t final_out[16];

        crypto_padding_apply_block(final_block, leftover_len ? leftover : NULL, leftover_len, padding);

        st = crypto_aes_ctr_xor_aes(aes, iv16, final_block, final_out, 16, block_offset);
        if (st != CRYPTO_OK) {
            secure_zero(final_block, sizeof(final_block));
            secure_zero(final_out, sizeof(final_out));
            free(in_buf);
            free(out_buf);
            return st;
        }

        if (fwrite(final_out, 1, 16, fout) != 16) {
            secure_zero(final_block, sizeof(final_block));
            secure_zero(final_out, sizeof(final_out));
            free(in_buf);
            free(out_buf);
            return CRYPTO_IO_ERROR;
        }

        secure_zero(final_block, sizeof(final_block));
        secure_zero(final_out, sizeof(final_out));
    }

    secure_zero(leftover, sizeof(leftover));
    free(in_buf);
    free(out_buf);
    return CRYPTO_OK;
}

crypto_status_t crypto_ffi_aes_ctr_encrypt_file(const uint8_t* key,
                                               size_t key_len_bytes,
                                               const uint8_t iv16[16],
                                               crypto_padding_t padding,
                                               const char* input_path,
                                               const char* output_path,
                                               int prefix_iv)
{
    FILE* fin;
    FILE* fout;
    crypto_aes_t aes;
    crypto_status_t st;

    if (!key || !iv16 || !input_path || !output_path) {
        return CRYPTO_INVALID_ARG;
    }

    if (!crypto_padding_supported(padding)) {
        return CRYPTO_UNSUPPORTED;
    }

    fin = fopen(input_path, "rb");
    if (!fin) {
        return CRYPTO_IO_ERROR;
    }

    fout = fopen(output_path, "wb");
    if (!fout) {
        fclose(fin);
        return CRYPTO_IO_ERROR;
    }

    if (prefix_iv) {
        if (fwrite(iv16, 1, 16, fout) != 16) {
            fclose(fin);
            fclose(fout);
            return CRYPTO_IO_ERROR;
        }
    }

    st = aes_key_init(&aes, key, key_len_bytes);
    if (st != CRYPTO_OK) {
        fclose(fin);
        fclose(fout);
        return st;
    }

    st = file_encrypt_internal(&aes, iv16, padding, fin, fout);

    crypto_aes_clear(&aes);
    fclose(fin);
    fclose(fout);
    return st;
}

static crypto_status_t file_decrypt_internal(const crypto_aes_t* aes,
                                            const uint8_t iv16[16],
                                            crypto_padding_t padding,
                                            FILE* fin,
                                            FILE* fout)
{
    crypto_status_t st;
    size_t chunk;
    uint8_t* buf;
    uint8_t* out_buf;
    uint8_t rem[32];
    size_t rem_len = 0;
    uint64_t block_offset = 0;

    st = parse_chunk_size(&chunk);
    if (st != CRYPTO_OK) {
        return st;
    }

    buf = (uint8_t*)malloc(chunk + 32);
    out_buf = (uint8_t*)malloc(chunk + 32);
    if (!buf || !out_buf) {
        free(buf);
        free(out_buf);
        return CRYPTO_INTERNAL_ERROR;
    }

    while (1) {
        size_t n = fread(buf + rem_len, 1, chunk, fin);
        size_t total;
        size_t process_len;
        size_t keep_len;

        if (n == 0) {
            if (ferror(fin)) {
                free(buf);
                free(out_buf);
                return CRYPTO_IO_ERROR;
            }
            break;
        }

        total = rem_len + n;
        if (total < 16) {
            rem_len = total;
            continue;
        }

        process_len = ((total - 16) / 16) * 16;
        keep_len = total - process_len;

        if (process_len) {
            st = crypto_aes_ctr_xor_aes(aes, iv16, buf, out_buf, process_len, block_offset);
            if (st != CRYPTO_OK) {
                free(buf);
                free(out_buf);
                return st;
            }
            if (fwrite(out_buf, 1, process_len, fout) != process_len) {
                free(buf);
                free(out_buf);
                return CRYPTO_IO_ERROR;
            }
            block_offset += (uint64_t)(process_len / 16);
        }

        if (keep_len) {
            memmove(rem, buf + process_len, keep_len);
        }
        memcpy(buf, rem, keep_len);
        rem_len = keep_len;
    }

    if (rem_len != 16) {
        free(buf);
        free(out_buf);
        return CRYPTO_BAD_PADDING;
    }

    {
        uint8_t last_plain[16];
        size_t last_len;

        st = crypto_aes_ctr_xor_aes(aes, iv16, buf, last_plain, 16, block_offset);
        if (st != CRYPTO_OK) {
            secure_zero(last_plain, sizeof(last_plain));
            free(buf);
            free(out_buf);
            return st;
        }

        st = crypto_padding_remove(last_plain, 16, padding, &last_len);
        if (st != CRYPTO_OK) {
            secure_zero(last_plain, sizeof(last_plain));
            free(buf);
            free(out_buf);
            return st;
        }

        if (last_len) {
            if (fwrite(last_plain, 1, last_len, fout) != last_len) {
                secure_zero(last_plain, sizeof(last_plain));
                free(buf);
                free(out_buf);
                return CRYPTO_IO_ERROR;
            }
        }

        secure_zero(last_plain, sizeof(last_plain));
    }

    secure_zero(rem, sizeof(rem));
    free(buf);
    free(out_buf);
    return CRYPTO_OK;
}

crypto_status_t crypto_ffi_aes_ctr_decrypt_file(const uint8_t* key,
                                               size_t key_len_bytes,
                                               const uint8_t iv16[16],
                                               crypto_padding_t padding,
                                               const char* input_path,
                                               const char* output_path,
                                               int prefix_iv)
{
    FILE* fin;
    FILE* fout;
    crypto_aes_t aes;
    crypto_status_t st;
    uint8_t used_iv[16];

    if (!key || !iv16 || !input_path || !output_path) {
        return CRYPTO_INVALID_ARG;
    }

    if (!crypto_padding_supported(padding)) {
        return CRYPTO_UNSUPPORTED;
    }

    fin = fopen(input_path, "rb");
    if (!fin) {
        return CRYPTO_IO_ERROR;
    }

    if (prefix_iv) {
        if (fread(used_iv, 1, 16, fin) != 16) {
            fclose(fin);
            return CRYPTO_IO_ERROR;
        }
    } else {
        memcpy(used_iv, iv16, 16);
    }

    fout = fopen(output_path, "wb");
    if (!fout) {
        fclose(fin);
        return CRYPTO_IO_ERROR;
    }

    st = aes_key_init(&aes, key, key_len_bytes);
    if (st != CRYPTO_OK) {
        fclose(fin);
        fclose(fout);
        secure_zero(used_iv, sizeof(used_iv));
        return st;
    }

    st = file_decrypt_internal(&aes, used_iv, padding, fin, fout);

    crypto_aes_clear(&aes);
    fclose(fin);
    fclose(fout);
    secure_zero(used_iv, sizeof(used_iv));
    return st;
}

crypto_status_t crypto_ffi_aes_gcm_encrypt_alloc(const uint8_t* key,
                                                size_t key_len_bytes,
                                                const uint8_t* iv,
                                                size_t iv_len,
                                                const uint8_t* aad,
                                                size_t aad_len,
                                                const uint8_t* plaintext,
                                                size_t plaintext_len,
                                                uint8_t** ciphertext_out,
                                                size_t* ciphertext_len_out,
                                                uint8_t tag16_out[16])
{
    uint8_t* out;
    crypto_status_t st;

    if (!key || !iv || !ciphertext_out || !ciphertext_len_out || !tag16_out) {
        return CRYPTO_INVALID_ARG;
    }

    if (plaintext_len && !plaintext) {
        return CRYPTO_INVALID_ARG;
    }

    if (aad_len && !aad) {
        return CRYPTO_INVALID_ARG;
    }

    out = (uint8_t*)malloc(plaintext_len ? plaintext_len : 1);
    if (!out) {
        return CRYPTO_INTERNAL_ERROR;
    }

    st = crypto_aes_gcm_encrypt(key, key_len_bytes, iv, iv_len, aad, aad_len, plaintext, plaintext_len, out, tag16_out);
    if (st != CRYPTO_OK) {
        secure_zero(out, plaintext_len);
        free(out);
        return st;
    }

    *ciphertext_out = out;
    *ciphertext_len_out = plaintext_len;
    return CRYPTO_OK;
}

crypto_status_t crypto_ffi_aes_gcm_decrypt_alloc(const uint8_t* key,
                                                size_t key_len_bytes,
                                                const uint8_t* iv,
                                                size_t iv_len,
                                                const uint8_t* aad,
                                                size_t aad_len,
                                                const uint8_t* ciphertext,
                                                size_t ciphertext_len,
                                                const uint8_t tag16[16],
                                                uint8_t** plaintext_out,
                                                size_t* plaintext_len_out)
{
    uint8_t* out;
    crypto_status_t st;

    if (!key || !iv || !ciphertext || !tag16 || !plaintext_out || !plaintext_len_out) {
        return CRYPTO_INVALID_ARG;
    }

    if (aad_len && !aad) {
        return CRYPTO_INVALID_ARG;
    }

    out = (uint8_t*)malloc(ciphertext_len ? ciphertext_len : 1);
    if (!out) {
        return CRYPTO_INTERNAL_ERROR;
    }

    st = crypto_aes_gcm_decrypt(key, key_len_bytes, iv, iv_len, aad, aad_len, ciphertext, ciphertext_len, tag16, out);
    if (st != CRYPTO_OK) {
        secure_zero(out, ciphertext_len);
        free(out);
        return st;
    }

    *plaintext_out = out;
    *plaintext_len_out = ciphertext_len;
    return CRYPTO_OK;
}

typedef struct cpu_gcm_xor_context_t {
    const crypto_aes_t* aes;
    const uint8_t* j0;
} cpu_gcm_xor_context_t;

static crypto_status_t cpu_gcm_xor_callback(void* context,
                                           const uint8_t* input,
                                           uint8_t* output,
                                           size_t len,
                                           uint64_t block_offset)
{
    const cpu_gcm_xor_context_t* ctx = (const cpu_gcm_xor_context_t*)context;

    if (!ctx || !ctx->aes || !ctx->j0) {
        return CRYPTO_INVALID_ARG;
    }

    return crypto_aes_ctr_xor_aes(ctx->aes, ctx->j0, input, output, len, block_offset);
}

crypto_status_t crypto_ffi_aes_gcm_encrypt_file(const uint8_t* key,
                                               size_t key_len_bytes,
                                               const uint8_t* iv,
                                               size_t iv_len,
                                               const uint8_t* aad,
                                               size_t aad_len,
                                               const char* input_path,
                                               const char* output_path,
                                               uint8_t tag16_out[16])
{
    FILE* fin;
    FILE* fout;
    crypto_aes_t aes;
    crypto_gcm_stream_state_t gcm;
    crypto_ctr_stream_state_t ctr;
    cpu_gcm_xor_context_t xor_ctx;
    crypto_status_t st;
    size_t chunk;
    uint8_t* in_buf;
    uint8_t* out_buf;

    if (!key || !iv || !input_path || !output_path || !tag16_out) {
        return CRYPTO_INVALID_ARG;
    }

    if (aad_len && !aad) {
        return CRYPTO_INVALID_ARG;
    }

    fin = fopen(input_path, "rb");
    if (!fin) {
        return CRYPTO_IO_ERROR;
    }

    fout = fopen(output_path, "wb");
    if (!fout) {
        fclose(fin);
        return CRYPTO_IO_ERROR;
    }

    st = parse_chunk_size(&chunk);
    if (st != CRYPTO_OK) {
        fclose(fin);
        fclose(fout);
        return st;
    }

    in_buf = (uint8_t*)malloc(chunk ? chunk : 1);
    out_buf = (uint8_t*)malloc(chunk ? chunk : 1);
    if (!in_buf || !out_buf) {
        free(in_buf);
        free(out_buf);
        fclose(fin);
        fclose(fout);
        return CRYPTO_INTERNAL_ERROR;
    }

    st = aes_key_init(&aes, key, key_len_bytes);
    if (st != CRYPTO_OK) {
        free(in_buf);
        free(out_buf);
        fclose(fin);
        fclose(fout);
        return st;
    }

    st = crypto_gcm_stream_init(&gcm, &aes, iv, iv_len, aad, aad_len);
    if (st != CRYPTO_OK) {
        crypto_aes_clear(&aes);
        free(in_buf);
        free(out_buf);
        fclose(fin);
        fclose(fout);
        return st;
    }

    crypto_ctr_stream_init(&ctr, 1u);
    xor_ctx.aes = &aes;
    xor_ctx.j0 = gcm.j0;

    while (1) {
        size_t n = fread(in_buf, 1, chunk, fin);

        if (n == 0) {
            if (ferror(fin)) {
                st = CRYPTO_IO_ERROR;
                break;
            }
            st = CRYPTO_OK;
            break;
        }

        st = crypto_ctr_stream_xor(&ctr, cpu_gcm_xor_callback, &xor_ctx, in_buf, out_buf, n);
        if (st != CRYPTO_OK) {
            break;
        }

        st = crypto_gcm_stream_update_ciphertext(&gcm, out_buf, n);
        if (st != CRYPTO_OK) {
            break;
        }

        if (fwrite(out_buf, 1, n, fout) != n) {
            st = CRYPTO_IO_ERROR;
            break;
        }
    }

    if (st == CRYPTO_OK) {
        st = crypto_gcm_stream_finalize_tag(&gcm, &aes, tag16_out);
    }

    crypto_ctr_stream_clear(&ctr);
    crypto_gcm_stream_clear(&gcm);
    crypto_aes_clear(&aes);
    secure_zero(in_buf, chunk);
    secure_zero(out_buf, chunk);
    free(in_buf);
    free(out_buf);
    fclose(fin);
    fclose(fout);

    if (st != CRYPTO_OK) {
        remove(output_path);
    }

    return st;
}

crypto_status_t crypto_ffi_aes_gcm_decrypt_file(const uint8_t* key,
                                               size_t key_len_bytes,
                                               const uint8_t* iv,
                                               size_t iv_len,
                                               const uint8_t* aad,
                                               size_t aad_len,
                                               const char* input_path,
                                               const char* output_path,
                                               const uint8_t tag16[16])
{
    FILE* fin;
    FILE* fout;
    crypto_aes_t aes;
    crypto_gcm_stream_state_t gcm;
    crypto_ctr_stream_state_t ctr;
    cpu_gcm_xor_context_t xor_ctx;
    crypto_status_t st;
    size_t chunk;
    uint8_t* in_buf;
    uint8_t* out_buf;
    uint8_t expected[16];

    if (!key || !iv || !input_path || !output_path || !tag16) {
        return CRYPTO_INVALID_ARG;
    }

    if (aad_len && !aad) {
        return CRYPTO_INVALID_ARG;
    }

    fin = fopen(input_path, "rb");
    if (!fin) {
        return CRYPTO_IO_ERROR;
    }

    fout = fopen(output_path, "wb");
    if (!fout) {
        fclose(fin);
        return CRYPTO_IO_ERROR;
    }

    st = parse_chunk_size(&chunk);
    if (st != CRYPTO_OK) {
        fclose(fin);
        fclose(fout);
        return st;
    }

    in_buf = (uint8_t*)malloc(chunk ? chunk : 1);
    out_buf = (uint8_t*)malloc(chunk ? chunk : 1);
    if (!in_buf || !out_buf) {
        free(in_buf);
        free(out_buf);
        fclose(fin);
        fclose(fout);
        return CRYPTO_INTERNAL_ERROR;
    }

    st = aes_key_init(&aes, key, key_len_bytes);
    if (st != CRYPTO_OK) {
        free(in_buf);
        free(out_buf);
        fclose(fin);
        fclose(fout);
        return st;
    }

    st = crypto_gcm_stream_init(&gcm, &aes, iv, iv_len, aad, aad_len);
    if (st != CRYPTO_OK) {
        crypto_aes_clear(&aes);
        free(in_buf);
        free(out_buf);
        fclose(fin);
        fclose(fout);
        return st;
    }

    crypto_ctr_stream_init(&ctr, 1u);
    xor_ctx.aes = &aes;
    xor_ctx.j0 = gcm.j0;

    while (1) {
        size_t n = fread(in_buf, 1, chunk, fin);

        if (n == 0) {
            if (ferror(fin)) {
                st = CRYPTO_IO_ERROR;
                break;
            }
            st = CRYPTO_OK;
            break;
        }

        st = crypto_gcm_stream_update_ciphertext(&gcm, in_buf, n);
        if (st != CRYPTO_OK) {
            break;
        }

        st = crypto_ctr_stream_xor(&ctr, cpu_gcm_xor_callback, &xor_ctx, in_buf, out_buf, n);
        if (st != CRYPTO_OK) {
            break;
        }

        if (fwrite(out_buf, 1, n, fout) != n) {
            st = CRYPTO_IO_ERROR;
            break;
        }
    }

    if (st == CRYPTO_OK) {
        st = crypto_gcm_stream_finalize_tag(&gcm, &aes, expected);
        if (st == CRYPTO_OK && memcmp(expected, tag16, 16) != 0) {
            st = CRYPTO_AUTH_FAILED;
        }
    }

    secure_zero(expected, sizeof(expected));
    crypto_ctr_stream_clear(&ctr);
    crypto_gcm_stream_clear(&gcm);
    crypto_aes_clear(&aes);
    secure_zero(in_buf, chunk);
    secure_zero(out_buf, chunk);
    free(in_buf);
    free(out_buf);
    fclose(fin);
    fclose(fout);

    if (st != CRYPTO_OK) {
        remove(output_path);
    }

    return st;
}

void crypto_ffi_free(void* p)
{
    free(p);
}
