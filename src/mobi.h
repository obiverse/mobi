/*
 * Mobi Protocol v21.0.0
 *
 * Derives a 21-digit identifier from a secp256k1 public key.
 * Display 12 digits to users. Store full 21. Resolve collisions progressively.
 *
 * Why 21? Bitcoin's number. And 10^21 = 1 sextillion values.
 * 50% collision probability at 44.7 billion users (far beyond human population).
 *
 * Algorithm: Rejection sampling for uniform distribution (zero bias).
 *
 * Copyright (c) 2024-2025 OBIVERSE LLC
 * Licensed under MIT OR Apache-2.0
 */

#ifndef MOBI_H
#define MOBI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * VERSION
 * ============================================================================ */

#define MOBI_VERSION_MAJOR    21
#define MOBI_VERSION_MINOR    0
#define MOBI_VERSION_PATCH    0
#define MOBI_VERSION_STRING   "21.0.0"

/* ============================================================================
 * CONSTANTS
 * ============================================================================ */

#define MOBI_PUBKEY_LEN       32   /* secp256k1 x-only pubkey bytes */
#define MOBI_PUBKEY_HEX_LEN   64   /* hex-encoded pubkey */

#define MOBI_FULL_LEN         21   /* canonical form: 21 digits */
#define MOBI_DISPLAY_LEN      12   /* display form: 12 digits */
#define MOBI_EXTENDED_LEN     15   /* extended form: 15 digits */
#define MOBI_LONG_LEN         18   /* long form: 18 digits */

/* Formatted lengths (with hyphens) */
#define MOBI_FULL_FMT_LEN     27   /* XXX-XXX-XXX-XXX-XXX-XXX-XXX */
#define MOBI_DISPLAY_FMT_LEN  15   /* XXX-XXX-XXX-XXX */
#define MOBI_EXTENDED_FMT_LEN 19   /* XXX-XXX-XXX-XXX-XXX */
#define MOBI_LONG_FMT_LEN     23   /* XXX-XXX-XXX-XXX-XXX-XXX */

/* ============================================================================
 * ERROR CODES
 * ============================================================================ */

typedef enum {
    MOBI_OK              =  0,
    MOBI_ERR_NULL        = -1,   /* Null pointer argument */
    MOBI_ERR_INVALID_HEX = -2,   /* Invalid hex character */
    MOBI_ERR_INVALID_LEN = -3,   /* Wrong input length */
    MOBI_ERR_INVALID_CHAR= -4,   /* Invalid character in mobi */
} mobi_error_t;

/* ============================================================================
 * DATA STRUCTURES
 * ============================================================================ */

/*
 * mobi_t: The complete mobi identity
 *
 * Contains all representations derived from a single pubkey.
 * All fields are deterministic - same pubkey always yields same values.
 */
typedef struct {
    char full[22];      /* 21 digits + null: canonical form (always unique) */
    char display[13];   /* 12 digits + null: human display form */
    char extended[16];  /* 15 digits + null: collision resolution */
    char lng[19];       /* 18 digits + null: extended resolution */
} mobi_t;

/* ============================================================================
 * CORE API
 * ============================================================================ */

/*
 * mobi_derive: Derive mobi from hex-encoded public key
 *
 * @param pubkey_hex  64-character hex string (x-only secp256k1 pubkey)
 * @param out         Output mobi_t structure
 * @return            MOBI_OK on success, error code otherwise
 *
 * Example:
 *   mobi_t m;
 *   mobi_derive("17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917", &m);
 *   printf("Display: %s\n", m.display);  // "879044656584"
 *   printf("Full:    %s\n", m.full);     // "879044656584686196443"
 */
mobi_error_t mobi_derive(const char *pubkey_hex, mobi_t *out);

/*
 * mobi_derive_bytes: Derive mobi from raw public key bytes
 *
 * @param pubkey  32-byte x-only public key
 * @param out     Output mobi_t structure
 * @return        MOBI_OK on success, error code otherwise
 */
mobi_error_t mobi_derive_bytes(const uint8_t *pubkey, mobi_t *out);

/* ============================================================================
 * FORMATTING API
 * ============================================================================ */

/*
 * mobi_format_display: Format 12-digit display with hyphens
 *
 * @param mobi    mobi_t structure
 * @param out     Output buffer (min 16 bytes)
 * @return        MOBI_OK on success
 *
 * Output: "XXX-XXX-XXX-XXX"
 */
mobi_error_t mobi_format_display(const mobi_t *mobi, char *out);

/*
 * mobi_format_extended: Format 15-digit extended with hyphens
 *
 * @param mobi    mobi_t structure
 * @param out     Output buffer (min 20 bytes)
 * @return        MOBI_OK on success
 *
 * Output: "XXX-XXX-XXX-XXX-XXX"
 */
mobi_error_t mobi_format_extended(const mobi_t *mobi, char *out);

/*
 * mobi_format_full: Format 21-digit canonical with hyphens
 *
 * @param mobi    mobi_t structure
 * @param out     Output buffer (min 28 bytes)
 * @return        MOBI_OK on success
 *
 * Output: "XXX-XXX-XXX-XXX-XXX-XXX-XXX"
 */
mobi_error_t mobi_format_full(const mobi_t *mobi, char *out);

/* ============================================================================
 * PARSING API
 * ============================================================================ */

/*
 * mobi_normalize: Strip formatting, validate digits
 *
 * Accepts: "650-073-047-435" or "650073047435" or "650 073 047 435"
 * Outputs: "650073047435" (digits only)
 *
 * @param input   Input string (any format)
 * @param out     Output buffer (min input_digit_count + 1)
 * @param out_len Size of output buffer
 * @return        Number of digits extracted, or negative error
 */
int mobi_normalize(const char *input, char *out, size_t out_len);

/*
 * mobi_validate: Check if string is valid mobi format
 *
 * @param mobi    Mobi string (12, 15, 18, or 21 digits)
 * @return        1 if valid, 0 if invalid
 */
int mobi_validate(const char *mobi);

/* ============================================================================
 * COMPARISON API
 * ============================================================================ */

/*
 * mobi_display_matches: Check if display forms match
 *
 * Compares first 12 digits of two mobis.
 *
 * @param a   First mobi (any length >= 12)
 * @param b   Second mobi (any length >= 12)
 * @return    1 if match, 0 if different
 */
int mobi_display_matches(const char *a, const char *b);

/*
 * mobi_full_matches: Check if full forms match
 *
 * Compares all 21 digits.
 *
 * @param a   First mobi_t
 * @param b   Second mobi_t
 * @return    1 if match, 0 if different
 */
int mobi_full_matches(const mobi_t *a, const mobi_t *b);

/* ============================================================================
 * UTILITY API
 * ============================================================================ */

/*
 * mobi_strerror: Get human-readable error message
 *
 * @param err   Error code
 * @return      Static string describing the error
 */
const char* mobi_strerror(mobi_error_t err);

#ifdef __cplusplus
}
#endif

#endif /* MOBI_H */
