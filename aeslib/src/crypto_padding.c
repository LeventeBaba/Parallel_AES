#include "crypto_padding.h"

#ifdef CRYPTO_PROFILE
#include "crypto_profile.h"
#include "crypto_timer.h"
#endif

static size_t crypto_padding_block_size(void)
{
    return 16;
}

int crypto_padding_supported(crypto_padding_t padding)
{
    return padding == CRYPTO_PADDING_PKCS7 ||
           padding == CRYPTO_PADDING_ANSIX923 ||
           padding == CRYPTO_PADDING_ISO7816_4 ||
           padding == CRYPTO_PADDING_ZERO ||
           padding == CRYPTO_PADDING_NONE;
}

crypto_status_t crypto_padding_padded_size(size_t n, crypto_padding_t padding, size_t* out_padded_size)
{
    size_t bs;
    size_t r;
    size_t pad;

    if (!out_padded_size) {
        return CRYPTO_INVALID_ARG;
    }
    *out_padded_size = 0;

    if (!crypto_padding_supported(padding)) {
        return CRYPTO_UNSUPPORTED;
    }

    bs = crypto_padding_block_size();
    r = n % bs;

    if (padding == CRYPTO_PADDING_ZERO) {
        pad = (r == 0) ? 0 : (bs - r);
        *out_padded_size = n + pad;
        return CRYPTO_OK;
    }

    if (padding == CRYPTO_PADDING_NONE) {
        if (r != 0) {
            return CRYPTO_INVALID_ARG;
        }
        *out_padded_size = n;
        return CRYPTO_OK;
    }

    pad = bs - r;
    if (pad == 0) {
        pad = bs;
    }
    *out_padded_size = n + pad;
    return CRYPTO_OK;
}

void crypto_padding_apply_block(uint8_t block[16], const uint8_t* tail, size_t tail_len, crypto_padding_t padding)
{
#ifdef CRYPTO_PROFILE
    uint64_t t0 = crypto_time_now_ns();
#endif
    size_t i;
    size_t pad_len = crypto_padding_block_size() - tail_len;

    for (i = 0; i < tail_len; i++) {
        block[i] = tail[i];
    }

    if (padding == CRYPTO_PADDING_PKCS7) {
        for (i = tail_len; i < crypto_padding_block_size(); i++) {
            block[i] = (uint8_t)pad_len;
        }
        #ifdef CRYPTO_PROFILE
        crypto_profile_add_padding_apply(crypto_time_now_ns() - t0);
        #endif
        return;
    }

    if (padding == CRYPTO_PADDING_ANSIX923) {
        for (i = tail_len; i < crypto_padding_block_size() - 1; i++) {
            block[i] = 0;
        }
        block[crypto_padding_block_size() - 1] = (uint8_t)pad_len;
        #ifdef CRYPTO_PROFILE
        crypto_profile_add_padding_apply(crypto_time_now_ns() - t0);
        #endif
        return;
    }

    if (padding == CRYPTO_PADDING_ISO7816_4) {
        if (tail_len < crypto_padding_block_size()) {
            block[tail_len] = 0x80;
            for (i = tail_len + 1; i < crypto_padding_block_size(); i++) {
                block[i] = 0;
            }
            #ifdef CRYPTO_PROFILE
            crypto_profile_add_padding_apply(crypto_time_now_ns() - t0);
            #endif
            return;
        }
    }

    if (padding == CRYPTO_PADDING_ZERO) {
        for (i = tail_len; i < crypto_padding_block_size(); i++) {
            block[i] = 0;
        }
        #ifdef CRYPTO_PROFILE
        crypto_profile_add_padding_apply(crypto_time_now_ns() - t0);
        #endif
        return;
    }

    for (i = tail_len; i < crypto_padding_block_size(); i++) {
        block[i] = 0;
    }
#ifdef CRYPTO_PROFILE
    crypto_profile_add_padding_apply(crypto_time_now_ns() - t0);
#endif
}

crypto_status_t crypto_padding_remove(const uint8_t* buf, size_t buf_len, crypto_padding_t padding, size_t* out_len)
{
#ifdef CRYPTO_PROFILE
    uint64_t t0 = crypto_time_now_ns();
#endif
    size_t pad_len;
    size_t i;

    if (!buf || !out_len) {
        return CRYPTO_INVALID_ARG;
    }

    if (buf_len == 0 || (buf_len % crypto_padding_block_size()) != 0) {
        return CRYPTO_BAD_PADDING;
    }

    if (!crypto_padding_supported(padding)) {
        return CRYPTO_UNSUPPORTED;
    }

    if (padding == CRYPTO_PADDING_NONE) {
        *out_len = buf_len;
#ifdef CRYPTO_PROFILE
        crypto_profile_add_padding_remove(crypto_time_now_ns() - t0);
#endif
        return CRYPTO_OK;
    }

    if (padding == CRYPTO_PADDING_ZERO) {
        size_t i2 = buf_len;
        while (i2 > 0 && buf[i2 - 1] == 0) {
            i2--;
        }
        *out_len = i2;
#ifdef CRYPTO_PROFILE
        crypto_profile_add_padding_remove(crypto_time_now_ns() - t0);
#endif
        return CRYPTO_OK;
    }

    if (padding == CRYPTO_PADDING_ISO7816_4) {
        size_t i2 = buf_len;
        size_t min_i;
        while (i2 > 0 && buf[i2 - 1] == 0) {
            i2--;
        }
        if (i2 == 0) {
            return CRYPTO_BAD_PADDING;
        }
        if (buf[i2 - 1] != 0x80) {
            return CRYPTO_BAD_PADDING;
        }
        min_i = (buf_len >= crypto_padding_block_size()) ? (buf_len - crypto_padding_block_size()) : 0;
        if ((i2 - 1) < min_i) {
            return CRYPTO_BAD_PADDING;
        }
        *out_len = i2 - 1;
#ifdef CRYPTO_PROFILE
        crypto_profile_add_padding_remove(crypto_time_now_ns() - t0);
#endif
        return CRYPTO_OK;
    }

    pad_len = buf[buf_len - 1];
    if (pad_len == 0 || pad_len > crypto_padding_block_size()) {
        return CRYPTO_BAD_PADDING;
    }

    if (pad_len > buf_len) {
        return CRYPTO_BAD_PADDING;
    }

    if (padding == CRYPTO_PADDING_PKCS7) {
        for (i = 0; i < pad_len; i++) {
            if (buf[buf_len - 1 - i] != (uint8_t)pad_len) {
                return CRYPTO_BAD_PADDING;
            }
        }
        *out_len = buf_len - pad_len;
#ifdef CRYPTO_PROFILE
        crypto_profile_add_padding_remove(crypto_time_now_ns() - t0);
#endif
        return CRYPTO_OK;
    }

    if (padding == CRYPTO_PADDING_ANSIX923) {
        if (pad_len == 1) {
            *out_len = buf_len - pad_len;
#ifdef CRYPTO_PROFILE
            crypto_profile_add_padding_remove(crypto_time_now_ns() - t0);
#endif
            return CRYPTO_OK;
        }
        for (i = 1; i < pad_len; i++) {
            if (buf[buf_len - 1 - i] != 0) {
                return CRYPTO_BAD_PADDING;
            }
        }
        *out_len = buf_len - pad_len;
#ifdef CRYPTO_PROFILE
        crypto_profile_add_padding_remove(crypto_time_now_ns() - t0);
#endif
        return CRYPTO_OK;
    }

    return CRYPTO_UNSUPPORTED;
}
