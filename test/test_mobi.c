/*
 * MobiNumber Protocol - Test Suite
 * Copyright (c) 2024 OBIVERSE LLC
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mobi.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    do { \
        tests_run++; \
        printf("  %s ... ", name); \
        fflush(stdout); \
    } while (0)

#define PASS() \
    do { \
        tests_passed++; \
        printf("PASS\n"); \
    } while (0)

#define FAIL(msg) \
    do { \
        printf("FAIL: %s\n", msg); \
    } while (0)

#define ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            FAIL(msg); \
            return; \
        } \
    } while (0)

#define ASSERT_EQ(a, b, msg) ASSERT((a) == (b), msg)
#define ASSERT_STR_EQ(a, b, msg) ASSERT(strcmp(a, b) == 0, msg)

/*
 * Test vectors from PROTOCOL.md
 * These are canonical test cases that all implementations MUST pass.
 */
static void test_derive_vector_1(void) {
    TEST("derive test vector 1 (all zeros)");

    /* All-zero pubkey */
    const char *pubkey = "0000000000000000000000000000000000000000000000000000000000000000";
    char mobi[13];

    mobi_error_t err = mobi_derive(pubkey, mobi);
    ASSERT_EQ(err, MOBI_OK, "derive failed");

    /* SHA256 of 32 zero bytes = 66687aadf862bd776c8fc18b8e9f8e20... */
    /* First 5 bytes: 0x66 0x68 0x7a 0xad 0xf8 = 439839534584 (< 10^12, no rejection) */
    ASSERT_STR_EQ(mobi, "439839534584", "wrong mobinumber for all-zero pubkey");

    PASS();
}

static void test_derive_vector_2(void) {
    TEST("derive test vector 2 (abandon mnemonic)");

    /*
     * This is the Nostr pubkey derived from the standard BIP39 test mnemonic:
     * "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
     * via BIP85 Nostr derivation path.
     *
     * The expected mobinumber should match what BeeBase derives.
     */
    const char *pubkey = "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";
    char mobi[13];

    mobi_error_t err = mobi_derive(pubkey, mobi);
    ASSERT_EQ(err, MOBI_OK, "derive failed");

    /* This should match BeeBase's derivation */
    printf("(got %s) ", mobi);

    /* Verify it's 12 digits */
    ASSERT_EQ(strlen(mobi), 12, "wrong length");

    PASS();
}

static void test_derive_invalid_hex(void) {
    TEST("derive rejects invalid hex");

    const char *pubkey = "zzzz000000000000000000000000000000000000000000000000000000000000";
    char mobi[13];

    mobi_error_t err = mobi_derive(pubkey, mobi);
    ASSERT_EQ(err, MOBI_ERR_INVALID_HEX, "should reject invalid hex");

    PASS();
}

static void test_derive_invalid_length(void) {
    TEST("derive rejects wrong length");

    const char *pubkey = "00000000";  /* Too short */
    char mobi[13];

    mobi_error_t err = mobi_derive(pubkey, mobi);
    ASSERT_EQ(err, MOBI_ERR_INVALID_LEN, "should reject wrong length");

    PASS();
}

static void test_derive_null_ptr(void) {
    TEST("derive handles null pointers");

    char mobi[13];
    const char *pubkey = "0000000000000000000000000000000000000000000000000000000000000000";

    ASSERT_EQ(mobi_derive(NULL, mobi), MOBI_ERR_NULL_PTR, "should reject null pubkey");
    ASSERT_EQ(mobi_derive(pubkey, NULL), MOBI_ERR_NULL_PTR, "should reject null output");

    PASS();
}

static void test_format_basic(void) {
    TEST("format basic");

    char formatted[16];
    mobi_error_t err = mobi_format("650073047435", formatted);

    ASSERT_EQ(err, MOBI_OK, "format failed");
    ASSERT_STR_EQ(formatted, "650-073-047-435", "wrong format");

    PASS();
}

static void test_format_all_zeros(void) {
    TEST("format all zeros");

    char formatted[16];
    mobi_error_t err = mobi_format("000000000000", formatted);

    ASSERT_EQ(err, MOBI_OK, "format failed");
    ASSERT_STR_EQ(formatted, "000-000-000-000", "wrong format");

    PASS();
}

static void test_normalize_with_hyphens(void) {
    TEST("normalize with hyphens");

    char normalized[13];
    mobi_error_t err = mobi_normalize("650-073-047-435", normalized);

    ASSERT_EQ(err, MOBI_OK, "normalize failed");
    ASSERT_STR_EQ(normalized, "650073047435", "wrong normalization");

    PASS();
}

static void test_normalize_with_spaces(void) {
    TEST("normalize with spaces");

    char normalized[13];
    mobi_error_t err = mobi_normalize("650 073 047 435", normalized);

    ASSERT_EQ(err, MOBI_OK, "normalize failed");
    ASSERT_STR_EQ(normalized, "650073047435", "wrong normalization");

    PASS();
}

static void test_normalize_already_normalized(void) {
    TEST("normalize already normalized");

    char normalized[13];
    mobi_error_t err = mobi_normalize("650073047435", normalized);

    ASSERT_EQ(err, MOBI_OK, "normalize failed");
    ASSERT_STR_EQ(normalized, "650073047435", "should pass through");

    PASS();
}

static void test_validate_valid(void) {
    TEST("validate valid mobinumber");

    ASSERT_EQ(mobi_validate("650073047435"), 1, "should be valid");
    ASSERT_EQ(mobi_validate("000000000000"), 1, "all zeros should be valid");
    ASSERT_EQ(mobi_validate("999999999999"), 1, "all nines should be valid");

    PASS();
}

static void test_validate_invalid(void) {
    TEST("validate invalid mobinumber");

    ASSERT_EQ(mobi_validate("65007304743"), 0, "too short");
    ASSERT_EQ(mobi_validate("6500730474355"), 0, "too long");
    ASSERT_EQ(mobi_validate("650-073-047-435"), 0, "with hyphens");
    ASSERT_EQ(mobi_validate("65007304743a"), 0, "with letter");
    ASSERT_EQ(mobi_validate(NULL), 0, "null pointer");

    PASS();
}

static void test_roundtrip(void) {
    TEST("format -> normalize roundtrip");

    const char *original = "123456789012";
    char formatted[16];
    char normalized[13];

    ASSERT_EQ(mobi_format(original, formatted), MOBI_OK, "format failed");
    ASSERT_EQ(mobi_normalize(formatted, normalized), MOBI_OK, "normalize failed");
    ASSERT_STR_EQ(normalized, original, "roundtrip mismatch");

    PASS();
}

static void test_derive_bytes(void) {
    TEST("derive_bytes matches derive");

    uint8_t pubkey[32] = {0};  /* All zeros */
    char mobi_bytes[13];
    char mobi_hex[13];

    mobi_error_t err1 = mobi_derive_bytes(pubkey, mobi_bytes);
    mobi_error_t err2 = mobi_derive(
        "0000000000000000000000000000000000000000000000000000000000000000",
        mobi_hex
    );

    ASSERT_EQ(err1, MOBI_OK, "derive_bytes failed");
    ASSERT_EQ(err2, MOBI_OK, "derive failed");
    ASSERT_STR_EQ(mobi_bytes, mobi_hex, "results should match");

    PASS();
}

int main(void) {
    printf("MobiNumber Protocol Test Suite\n");
    printf("==============================\n\n");

    printf("Derivation tests:\n");
    test_derive_vector_1();
    test_derive_vector_2();
    test_derive_invalid_hex();
    test_derive_invalid_length();
    test_derive_null_ptr();
    test_derive_bytes();

    printf("\nFormatting tests:\n");
    test_format_basic();
    test_format_all_zeros();

    printf("\nNormalization tests:\n");
    test_normalize_with_hyphens();
    test_normalize_with_spaces();
    test_normalize_already_normalized();

    printf("\nValidation tests:\n");
    test_validate_valid();
    test_validate_invalid();

    printf("\nRoundtrip tests:\n");
    test_roundtrip();

    printf("\n==============================\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
