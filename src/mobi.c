/*
 * MobiNumber Protocol v1.0 - Reference Implementation
 *
 * Derives a 12-digit human-readable identifier from a secp256k1 public key.
 * Uses rejection sampling to ensure uniform distribution across all 10^12 values.
 *
 * Copyright (c) 2024 OBIVERSE LLC
 * Licensed under MIT OR Apache-2.0
 */

#include "mobi.h"
#include <string.h>
#include <ctype.h>

/*
 * SHA-256 Implementation (standalone, no dependencies)
 * Based on FIPS 180-4
 */

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

    /* Prepare message schedule */
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
    }

    /* Initialize working variables */
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    /* Main loop */
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K256[i] + w[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    /* Add to state */
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
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

    /* Save original bit count before padding corrupts it */
    bits = ctx->count * 8;

    /* Get current buffer position */
    idx = (size_t)(ctx->count & 0x3F);

    /* Copy current buffer to final block */
    memcpy(final_block, ctx->buffer, idx);

    /* Add 0x80 padding byte */
    final_block[idx++] = 0x80;

    /* Determine if we need one or two blocks */
    if (idx > 56) {
        /* Need two blocks - zero rest of first, process, then second */
        memset(final_block + idx, 0, SHA256_BLOCK_SIZE - idx);
        sha256_transform(ctx, final_block);
        memset(final_block, 0, 56);
    } else {
        /* Single block - zero up to length field */
        memset(final_block + idx, 0, 56 - idx);
    }

    /* Append length in bits (big-endian, 8 bytes) */
    final_block[56] = (uint8_t)(bits >> 56);
    final_block[57] = (uint8_t)(bits >> 48);
    final_block[58] = (uint8_t)(bits >> 40);
    final_block[59] = (uint8_t)(bits >> 32);
    final_block[60] = (uint8_t)(bits >> 24);
    final_block[61] = (uint8_t)(bits >> 16);
    final_block[62] = (uint8_t)(bits >> 8);
    final_block[63] = (uint8_t)(bits);

    /* Process final block */
    sha256_transform(ctx, final_block);

    /* Output digest (big-endian) */
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

/*
 * Hex utilities
 */

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

/*
 * MobiNumber derivation with rejection sampling
 *
 * Algorithm:
 * 1. hash = SHA256(pubkey_bytes)
 * 2. Extract 5 bytes from hash[offset:offset+5] as big-endian u40
 * 3. If value >= 10^12, increment offset (mod 28) and retry
 * 4. Output: value as 12-digit zero-padded decimal string
 *
 * The rejection sampling ensures uniform distribution across all 10^12 values.
 * Expected iterations: ~1.1 (since 10^12 / 2^40 ≈ 0.909)
 */

#define MOBI_MAX_VALUE 1000000000000ULL  /* 10^12 */
#define MOBI_HASH_WINDOW 5               /* bytes to extract */
#define MOBI_MAX_OFFSET 28               /* SHA256_DIGEST_SIZE - MOBI_HASH_WINDOW + 1 */

mobi_error_t mobi_derive_bytes(const uint8_t *pubkey, char *out) {
    uint8_t hash[SHA256_DIGEST_SIZE];
    uint64_t value;
    int offset;
    int i;

    if (pubkey == NULL || out == NULL) {
        return MOBI_ERR_NULL_PTR;
    }

    /* Hash the public key */
    sha256(pubkey, MOBI_PUBKEY_LEN, hash);

    /* Rejection sampling loop */
    for (offset = 0; offset < MOBI_MAX_OFFSET; offset++) {
        /* Extract 5 bytes as big-endian u40 */
        value = 0;
        for (i = 0; i < MOBI_HASH_WINDOW; i++) {
            value = (value << 8) | hash[offset + i];
        }

        /* Check if value is in valid range */
        if (value < MOBI_MAX_VALUE) {
            /* Convert to 12-digit string */
            for (i = MOBI_NUMBER_LEN - 1; i >= 0; i--) {
                out[i] = '0' + (value % 10);
                value /= 10;
            }
            out[MOBI_NUMBER_LEN] = '\0';
            return MOBI_OK;
        }
    }

    /*
     * Extremely unlikely: all 28 windows exceeded 10^12.
     * Probability: < (1 - 0.909)^28 ≈ 10^-29
     * Fall back to modulo (still secure, just 0.0001% non-uniform)
     */
    value = 0;
    for (i = 0; i < MOBI_HASH_WINDOW; i++) {
        value = (value << 8) | hash[i];
    }
    value = value % MOBI_MAX_VALUE;

    for (i = MOBI_NUMBER_LEN - 1; i >= 0; i--) {
        out[i] = '0' + (value % 10);
        value /= 10;
    }
    out[MOBI_NUMBER_LEN] = '\0';
    return MOBI_OK;
}

mobi_error_t mobi_derive(const char *pubkey_hex, char *out) {
    uint8_t pubkey[MOBI_PUBKEY_LEN];
    size_t hex_len;

    if (pubkey_hex == NULL || out == NULL) {
        return MOBI_ERR_NULL_PTR;
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

mobi_error_t mobi_format(const char *mobi, char *out) {
    int i, j;

    if (mobi == NULL || out == NULL) {
        return MOBI_ERR_NULL_PTR;
    }

    if (strlen(mobi) != MOBI_NUMBER_LEN) {
        return MOBI_ERR_INVALID_LEN;
    }

    /* Validate all digits */
    for (i = 0; i < MOBI_NUMBER_LEN; i++) {
        if (!isdigit((unsigned char)mobi[i])) {
            return MOBI_ERR_INVALID_HEX;  /* Reuse error for invalid digit */
        }
    }

    /* Format as XXX-XXX-XXX-XXX */
    j = 0;
    for (i = 0; i < MOBI_NUMBER_LEN; i++) {
        if (i > 0 && i % 3 == 0) {
            out[j++] = '-';
        }
        out[j++] = mobi[i];
    }
    out[j] = '\0';

    return MOBI_OK;
}

mobi_error_t mobi_normalize(const char *input, char *out) {
    size_t len;
    int i, j;

    if (input == NULL || out == NULL) {
        return MOBI_ERR_NULL_PTR;
    }

    len = strlen(input);

    /* Extract digits only */
    j = 0;
    for (i = 0; i < (int)len && j < MOBI_NUMBER_LEN; i++) {
        if (isdigit((unsigned char)input[i])) {
            out[j++] = input[i];
        } else if (input[i] != '-' && input[i] != ' ') {
            /* Invalid character (not digit, hyphen, or space) */
            return MOBI_ERR_INVALID_HEX;
        }
    }
    out[j] = '\0';

    /* Validate length */
    if (j != MOBI_NUMBER_LEN) {
        return MOBI_ERR_INVALID_LEN;
    }

    return MOBI_OK;
}

int mobi_validate(const char *mobi) {
    int i;

    if (mobi == NULL) {
        return 0;
    }

    if (strlen(mobi) != MOBI_NUMBER_LEN) {
        return 0;
    }

    for (i = 0; i < MOBI_NUMBER_LEN; i++) {
        if (!isdigit((unsigned char)mobi[i])) {
            return 0;
        }
    }

    return 1;
}
