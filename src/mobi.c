/*
 * Mobi Protocol v21.0.0 - Reference Implementation
 *
 * Derives a 21-digit identifier from a secp256k1 public key.
 * Pure math. No network. Deterministic. Uniform distribution.
 *
 * Algorithm (rejection sampling for zero bias):
 *   1. For round = 0 to 255:
 *      a. If round == 0: hash = SHA256(pubkey)
 *         Else: hash = SHA256(pubkey || round)
 *      b. value = first 9 bytes as big-endian 72-bit integer
 *      c. If value < 10^21: return zero_pad(value, 21)
 *   2. Unreachable (probability < 10^-25)
 *
 * Why rejection sampling?
 *   - 2^72 = 4.72 × 10^21, so ~21% of 72-bit values are valid
 *   - Modulo would bias values 0 to 722... by ~25%
 *   - Rejection sampling ensures perfect uniformity
 *   - Expected rounds: ~4.7 (fast in practice)
 *
 * Copyright (c) 2024-2025 OBIVERSE LLC
 * Licensed under MIT OR Apache-2.0
 */

#include "mobi.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>

/* ============================================================================
 * SHA-256 IMPLEMENTATION (FIPS 180-4, standalone)
 * ============================================================================ */

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[SHA256_BLOCK_SIZE];
} sha256_ctx;

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)  (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define EP1(x)  (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SIG0(x) (ROTR32(x, 7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

static void sha256_init(sha256_ctx *ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

static void sha256_transform(sha256_ctx *ctx, const uint8_t *block) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K256[i] + w[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    size_t i, idx;
    idx = (size_t)(ctx->count & 0x3F);
    ctx->count += len;
    for (i = 0; i < len; i++) {
        ctx->buffer[idx++] = data[i];
        if (idx == SHA256_BLOCK_SIZE) {
            sha256_transform(ctx, ctx->buffer);
            idx = 0;
        }
    }
}

static void sha256_final(sha256_ctx *ctx, uint8_t *digest) {
    uint8_t final_block[SHA256_BLOCK_SIZE * 2];
    uint64_t bits;
    size_t idx;
    int i;

    bits = ctx->count * 8;
    idx = (size_t)(ctx->count & 0x3F);
    memcpy(final_block, ctx->buffer, idx);
    final_block[idx++] = 0x80;

    if (idx > 56) {
        memset(final_block + idx, 0, SHA256_BLOCK_SIZE - idx);
        sha256_transform(ctx, final_block);
        memset(final_block, 0, 56);
    } else {
        memset(final_block + idx, 0, 56 - idx);
    }

    final_block[56] = (uint8_t)(bits >> 56);
    final_block[57] = (uint8_t)(bits >> 48);
    final_block[58] = (uint8_t)(bits >> 40);
    final_block[59] = (uint8_t)(bits >> 32);
    final_block[60] = (uint8_t)(bits >> 24);
    final_block[61] = (uint8_t)(bits >> 16);
    final_block[62] = (uint8_t)(bits >> 8);
    final_block[63] = (uint8_t)(bits);

    sha256_transform(ctx, final_block);

    for (i = 0; i < 8; i++) {
        digest[i * 4] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

static void sha256(const uint8_t *data, size_t len, uint8_t *digest) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}

/* ============================================================================
 * HEX UTILITIES
 * ============================================================================ */

static int hex_char_to_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *hex, size_t hex_len, uint8_t *out, size_t out_len) {
    size_t i;
    int hi, lo;

    if (hex_len % 2 != 0) return -1;
    if (out_len < hex_len / 2) return -1;

    for (i = 0; i < hex_len / 2; i++) {
        hi = hex_char_to_nibble(hex[i * 2]);
        lo = hex_char_to_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* ============================================================================
 * BIG NUMBER OPERATIONS (72-bit arithmetic, portable C99)
 * ============================================================================ */

/*
 * Math recap:
 *   - 10^21 = 1,000,000,000,000,000,000,000 (22 decimal digits)
 *   - 2^72  = 4,722,366,482,869,645,213,696 (22 decimal digits)
 *   - 10^21 / 2^72 ≈ 0.212 (21.2% acceptance rate)
 *   - Expected rounds for rejection sampling: ~4.7
 *
 * We extract 9 bytes (72 bits), convert to decimal, check if < 10^21.
 * Simple digit counting works: 10^21 has 22 digits, so accept if <= 21 digits.
 */

/*
 * Convert 9 bytes (72 bits) to decimal and check if < 10^21.
 *
 * Returns 1 if valid (value < 10^21), writes 21-digit zero-padded result.
 * Returns 0 if should reject (value >= 10^21).
 */
static int try_convert_hash(const uint8_t *hash, char *out) {
    uint8_t work[10] = {0};
    char digits[24] = {0};
    int num_digits = 0;
    int i;

    /* Copy 9 bytes with leading zero for clean division */
    for (i = 0; i < 9; i++) {
        work[i + 1] = hash[i];
    }

    /* Extract digits via repeated division by 10 (big-endian long division) */
    while (1) {
        int all_zero = 1;
        for (i = 0; i < 10; i++) {
            if (work[i] != 0) { all_zero = 0; break; }
        }
        if (all_zero) break;

        uint32_t remainder = 0;
        for (i = 0; i < 10; i++) {
            uint32_t current = remainder * 256 + work[i];
            work[i] = (uint8_t)(current / 10);
            remainder = current % 10;
        }

        /* Prepend digit (extracting from least significant) */
        memmove(digits + 1, digits, (size_t)num_digits + 1);
        digits[0] = '0' + (char)remainder;
        num_digits++;
    }

    if (num_digits == 0) {
        digits[0] = '0';
        num_digits = 1;
    }

    /*
     * Rejection check: value must be < 10^21
     *
     * 10^21 = "1" followed by 21 zeros = 22 decimal digits
     * 2^72 max = 4,722,366,482,869,645,213,695 = 22 decimal digits
     *
     * If num_digits <= 21: value < 10^21, accept
     * If num_digits == 22: value >= 10^21, reject
     */
    if (num_digits > 21) {
        return 0;  /* Reject: value >= 10^21 */
    }

    /* Accept: left-pad with zeros to 21 digits */
    int pad = 21 - num_digits;
    memset(out, '0', (size_t)pad);
    memcpy(out + pad, digits, (size_t)num_digits);
    out[21] = '\0';
    return 1;
}

/* ============================================================================
 * CORE API IMPLEMENTATION
 * ============================================================================ */

/*
 * Maximum rejection sampling rounds before giving up.
 * Probability of reaching this: (1 - 0.212)^256 ≈ 10^-25
 */
#define MOBI_MAX_ROUNDS 256

mobi_error_t mobi_derive_bytes(const uint8_t *pubkey, mobi_t *out) {
    uint8_t hash[SHA256_DIGEST_SIZE];
    uint8_t input[MOBI_PUBKEY_LEN + 1];  /* pubkey + round byte */
    int round;

    if (pubkey == NULL || out == NULL) {
        return MOBI_ERR_NULL;
    }

    /* Copy pubkey for potential round-appending */
    memcpy(input, pubkey, MOBI_PUBKEY_LEN);

    /*
     * Rejection sampling loop:
     *   Round 0: hash = SHA256(pubkey)
     *   Round N: hash = SHA256(pubkey || N)
     *
     * Accept if first 9 bytes of hash, as decimal, < 10^21.
     * Expected rounds: ~4.7 (21.2% acceptance rate)
     */
    for (round = 0; round < MOBI_MAX_ROUNDS; round++) {
        if (round == 0) {
            sha256(pubkey, MOBI_PUBKEY_LEN, hash);
        } else {
            input[MOBI_PUBKEY_LEN] = (uint8_t)round;
            sha256(input, MOBI_PUBKEY_LEN + 1, hash);
        }

        if (try_convert_hash(hash, out->full)) {
            /* Success: extract prefix forms */
            memcpy(out->display, out->full, MOBI_DISPLAY_LEN);
            out->display[MOBI_DISPLAY_LEN] = '\0';

            memcpy(out->extended, out->full, MOBI_EXTENDED_LEN);
            out->extended[MOBI_EXTENDED_LEN] = '\0';

            memcpy(out->lng, out->full, MOBI_LONG_LEN);
            out->lng[MOBI_LONG_LEN] = '\0';

            return MOBI_OK;
        }
    }

    /*
     * Unreachable in practice (probability < 10^-25).
     * If somehow reached, return error rather than biased result.
     */
    return MOBI_ERR_INVALID_LEN;  /* Reuse error code for this edge case */
}

mobi_error_t mobi_derive(const char *pubkey_hex, mobi_t *out) {
    uint8_t pubkey[MOBI_PUBKEY_LEN];
    size_t hex_len;

    if (pubkey_hex == NULL || out == NULL) {
        return MOBI_ERR_NULL;
    }

    hex_len = strlen(pubkey_hex);
    if (hex_len != MOBI_PUBKEY_HEX_LEN) {
        return MOBI_ERR_INVALID_LEN;
    }

    if (hex_decode(pubkey_hex, hex_len, pubkey, MOBI_PUBKEY_LEN) != 0) {
        return MOBI_ERR_INVALID_HEX;
    }

    return mobi_derive_bytes(pubkey, out);
}

/* ============================================================================
 * FORMATTING API IMPLEMENTATION
 * ============================================================================ */

mobi_error_t mobi_format_display(const mobi_t *mobi, char *out) {
    if (mobi == NULL || out == NULL) {
        return MOBI_ERR_NULL;
    }

    /* Format: XXX-XXX-XXX-XXX */
    sprintf(out, "%.3s-%.3s-%.3s-%.3s",
            mobi->display, mobi->display + 3,
            mobi->display + 6, mobi->display + 9);

    return MOBI_OK;
}

mobi_error_t mobi_format_extended(const mobi_t *mobi, char *out) {
    if (mobi == NULL || out == NULL) {
        return MOBI_ERR_NULL;
    }

    /* Format: XXX-XXX-XXX-XXX-XXX */
    sprintf(out, "%.3s-%.3s-%.3s-%.3s-%.3s",
            mobi->extended, mobi->extended + 3, mobi->extended + 6,
            mobi->extended + 9, mobi->extended + 12);

    return MOBI_OK;
}

mobi_error_t mobi_format_full(const mobi_t *mobi, char *out) {
    if (mobi == NULL || out == NULL) {
        return MOBI_ERR_NULL;
    }

    /* Format: XXX-XXX-XXX-XXX-XXX-XXX-XXX */
    sprintf(out, "%.3s-%.3s-%.3s-%.3s-%.3s-%.3s-%.3s",
            mobi->full, mobi->full + 3, mobi->full + 6, mobi->full + 9,
            mobi->full + 12, mobi->full + 15, mobi->full + 18);

    return MOBI_OK;
}

/* ============================================================================
 * PARSING API IMPLEMENTATION
 * ============================================================================ */

int mobi_normalize(const char *input, char *out, size_t out_len) {
    size_t in_len;
    int digit_count = 0;
    size_t i;

    if (input == NULL || out == NULL) {
        return MOBI_ERR_NULL;
    }

    in_len = strlen(input);

    /* Extract digits only, skip common separators */
    for (i = 0; i < in_len && (size_t)digit_count < out_len - 1; i++) {
        if (isdigit((unsigned char)input[i])) {
            out[digit_count++] = input[i];
        } else if (input[i] != '-' && input[i] != ' ' && input[i] != '.' &&
                   input[i] != '(' && input[i] != ')') {
            return MOBI_ERR_INVALID_CHAR;
        }
    }
    out[digit_count] = '\0';

    return digit_count;
}

int mobi_validate(const char *mobi) {
    size_t len;
    size_t i;

    if (mobi == NULL) {
        return 0;
    }

    len = strlen(mobi);

    /* Valid lengths: 12, 15, 18, 21 */
    if (len != 12 && len != 15 && len != 18 && len != 21) {
        return 0;
    }

    /* All characters must be digits */
    for (i = 0; i < len; i++) {
        if (!isdigit((unsigned char)mobi[i])) {
            return 0;
        }
    }

    return 1;
}

/* ============================================================================
 * COMPARISON API IMPLEMENTATION
 * ============================================================================ */

int mobi_display_matches(const char *a, const char *b) {
    if (a == NULL || b == NULL) {
        return 0;
    }
    if (strlen(a) < 12 || strlen(b) < 12) {
        return 0;
    }
    return memcmp(a, b, 12) == 0;
}

int mobi_full_matches(const mobi_t *a, const mobi_t *b) {
    if (a == NULL || b == NULL) {
        return 0;
    }
    return memcmp(a->full, b->full, 21) == 0;
}

/* ============================================================================
 * UTILITY API IMPLEMENTATION
 * ============================================================================ */

const char* mobi_strerror(mobi_error_t err) {
    switch (err) {
        case MOBI_OK:              return "Success";
        case MOBI_ERR_NULL:        return "Null pointer argument";
        case MOBI_ERR_INVALID_HEX: return "Invalid hexadecimal character";
        case MOBI_ERR_INVALID_LEN: return "Invalid input length";
        case MOBI_ERR_INVALID_CHAR:return "Invalid character in mobi";
        default:                     return "Unknown error";
    }
}
