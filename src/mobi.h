/*
 * MobiNumber Protocol v1.0
 *
 * Derives a 12-digit human-readable identifier from a secp256k1 public key.
 *
 * Copyright (c) 2024 OBIVERSE LLC
 * Licensed under MIT OR Apache-2.0
 */

#ifndef MOBI_H
#define MOBI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version */
#define MOBI_VERSION_MAJOR 1
#define MOBI_VERSION_MINOR 0
#define MOBI_VERSION_PATCH 0

/* Constants */
#define MOBI_PUBKEY_LEN     32   /* secp256k1 x-only pubkey */
#define MOBI_PUBKEY_HEX_LEN 64   /* hex-encoded pubkey */
#define MOBI_NUMBER_LEN     12   /* output digits */
#define MOBI_FORMATTED_LEN  15   /* with hyphens: XXX-XXX-XXX-XXX */

/* Error codes */
typedef enum {
    MOBI_OK = 0,
    MOBI_ERR_NULL_PTR = -1,
    MOBI_ERR_INVALID_HEX = -2,
    MOBI_ERR_INVALID_LEN = -3,
} mobi_error_t;

/**
 * Derive mobinumber from hex-encoded public key.
 *
 * @param pubkey_hex  64-character hex string (lowercase)
 * @param out         Output buffer, must be at least MOBI_NUMBER_LEN + 1 bytes
 * @return            MOBI_OK on success, error code otherwise
 *
 * Example:
 *   char mobi[13];
 *   mobi_derive("7f3b...a9c1", mobi);
 *   // mobi = "650073047435"
 */
mobi_error_t mobi_derive(const char *pubkey_hex, char *out);

/**
 * Derive mobinumber from raw public key bytes.
 *
 * @param pubkey  32-byte public key
 * @param out     Output buffer, must be at least MOBI_NUMBER_LEN + 1 bytes
 * @return        MOBI_OK on success, error code otherwise
 */
mobi_error_t mobi_derive_bytes(const uint8_t *pubkey, char *out);

/**
 * Format mobinumber with hyphens.
 *
 * @param mobi    12-digit mobinumber string
 * @param out     Output buffer, must be at least MOBI_FORMATTED_LEN + 1 bytes
 * @return        MOBI_OK on success, error code otherwise
 *
 * Example:
 *   char formatted[16];
 *   mobi_format("650073047435", formatted);
 *   // formatted = "650-073-047-435"
 */
mobi_error_t mobi_format(const char *mobi, char *out);

/**
 * Normalize mobinumber (remove hyphens, validate).
 *
 * @param input   Mobinumber string (with or without hyphens)
 * @param out     Output buffer, must be at least MOBI_NUMBER_LEN + 1 bytes
 * @return        MOBI_OK on success, error code otherwise
 */
mobi_error_t mobi_normalize(const char *input, char *out);

/**
 * Validate mobinumber format.
 *
 * @param mobi    Mobinumber string (normalized, 12 digits)
 * @return        1 if valid, 0 if invalid
 */
int mobi_validate(const char *mobi);

#ifdef __cplusplus
}
#endif

#endif /* MOBI_H */
