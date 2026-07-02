#ifndef CRYPTO_STATUS_H
#define CRYPTO_STATUS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum crypto_status_t {
    CRYPTO_OK = 0,
    CRYPTO_INVALID_ARG = -1,
    CRYPTO_BUFFER_TOO_SMALL = -2,
    CRYPTO_BAD_PADDING = -3,
    CRYPTO_IO_ERROR = -4,
    CRYPTO_UNSUPPORTED = -5,
    CRYPTO_INTERNAL_ERROR = -6,
    CRYPTO_AUTH_FAILED = -7
} crypto_status_t;

#ifdef __cplusplus
}
#endif

#endif
