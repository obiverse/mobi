/*
 * Mobi Protocol - Test Suite
 * Copyright (c) 2024-2025 OBIVERSE LLC
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

/* ============================================================================
 * DERIVATION TESTS
 * ============================================================================ */

static void test_derive_all_zeros(void) {
    TEST("derive all-zero pubkey (canonical vector)");

    const char *pubkey = "0000000000000000000000000000000000000000000000000000000000000000";
    mobi_t m;

    mobi_error_t err = mobi_derive(pubkey, &m);
    ASSERT_EQ(err, MOBI_OK, "derive failed");

    /* Canonical test vector - MUST match spec */
    ASSERT_STR_EQ(m.full, "587135537154686717107", "full must match canonical vector");
    ASSERT_STR_EQ(m.display, "587135537154", "display must match canonical vector");
    ASSERT_STR_EQ(m.extended, "587135537154686", "extended must match canonical vector");
    ASSERT_STR_EQ(m.lng, "587135537154686717", "lng must match canonical vector");

    /* Verify lengths */
    ASSERT_EQ(strlen(m.full), 21, "full should be 21 digits");
    ASSERT_EQ(strlen(m.display), 12, "display should be 12 digits");
    ASSERT_EQ(strlen(m.extended), 15, "extended should be 15 digits");
    ASSERT_EQ(strlen(m.lng), 18, "long should be 18 digits");

    /* Verify prefix consistency */
    ASSERT(memcmp(m.display, m.full, 12) == 0, "display should be prefix of full");
    ASSERT(memcmp(m.extended, m.full, 15) == 0, "extended should be prefix of full");
    ASSERT(memcmp(m.lng, m.full, 18) == 0, "long should be prefix of full");

    PASS();
}

static void test_derive_abandon_mnemonic(void) {
    TEST("derive abandon mnemonic pubkey (canonical vector)");

    /*
     * Nostr pubkey derived from BIP-85 test mnemonic:
     * "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
     */
    const char *pubkey = "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";
    mobi_t m;

    mobi_error_t err = mobi_derive(pubkey, &m);
    ASSERT_EQ(err, MOBI_OK, "derive failed");

    /* Canonical test vector - MUST match spec */
    ASSERT_STR_EQ(m.full, "879044656584686196443", "full must match canonical vector");
    ASSERT_STR_EQ(m.display, "879044656584", "display must match canonical vector");

    PASS();
}

static void test_derive_deterministic(void) {
    TEST("derive is deterministic");

    const char *pubkey = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd";
    mobi_t m1, m2;

    mobi_derive(pubkey, &m1);
    mobi_derive(pubkey, &m2);

    ASSERT_STR_EQ(m1.full, m2.full, "same pubkey should yield same mobi");
    ASSERT_STR_EQ(m1.display, m2.display, "display should match");

    PASS();
}

static void test_derive_different_pubkeys(void) {
    TEST("different pubkeys yield different mobis");

    const char *pk1 = "0000000000000000000000000000000000000000000000000000000000000000";
    const char *pk2 = "0000000000000000000000000000000000000000000000000000000000000001";
    mobi_t m1, m2;

    mobi_derive(pk1, &m1);
    mobi_derive(pk2, &m2);

    /* Full forms should differ (with overwhelming probability) */
    ASSERT(strcmp(m1.full, m2.full) != 0, "different pubkeys should yield different mobis");

    PASS();
}

static void test_derive_invalid_hex(void) {
    TEST("derive rejects invalid hex");

    const char *pubkey = "zzzz000000000000000000000000000000000000000000000000000000000000";
    mobi_t m;

    mobi_error_t err = mobi_derive(pubkey, &m);
    ASSERT_EQ(err, MOBI_ERR_INVALID_HEX, "should reject invalid hex");

    PASS();
}

static void test_derive_invalid_length(void) {
    TEST("derive rejects wrong length");

    const char *pubkey = "00000000";  /* Too short */
    mobi_t m;

    mobi_error_t err = mobi_derive(pubkey, &m);
    ASSERT_EQ(err, MOBI_ERR_INVALID_LEN, "should reject wrong length");

    PASS();
}

static void test_derive_null_ptr(void) {
    TEST("derive handles null pointers");

    mobi_t m;
    const char *pubkey = "0000000000000000000000000000000000000000000000000000000000000000";

    ASSERT_EQ(mobi_derive(NULL, &m), MOBI_ERR_NULL, "should reject null pubkey");
    ASSERT_EQ(mobi_derive(pubkey, NULL), MOBI_ERR_NULL, "should reject null output");

    PASS();
}

/* ============================================================================
 * FORMATTING TESTS
 * ============================================================================ */

static void test_format_display(void) {
    TEST("format display (12 digits)");

    const char *pubkey = "0000000000000000000000000000000000000000000000000000000000000000";
    mobi_t m;
    char formatted[20];

    mobi_derive(pubkey, &m);
    mobi_error_t err = mobi_format_display(&m, formatted);

    ASSERT_EQ(err, MOBI_OK, "format failed");
    ASSERT_EQ(strlen(formatted), 15, "format should be 15 chars (XXX-XXX-XXX-XXX)");
    ASSERT_EQ(formatted[3], '-', "should have hyphen at position 3");
    ASSERT_EQ(formatted[7], '-', "should have hyphen at position 7");
    ASSERT_EQ(formatted[11], '-', "should have hyphen at position 11");

    printf("(%s) ", formatted);
    PASS();
}

static void test_format_extended(void) {
    TEST("format extended (15 digits)");

    const char *pubkey = "0000000000000000000000000000000000000000000000000000000000000000";
    mobi_t m;
    char formatted[24];

    mobi_derive(pubkey, &m);
    mobi_error_t err = mobi_format_extended(&m, formatted);

    ASSERT_EQ(err, MOBI_OK, "format failed");
    ASSERT_EQ(strlen(formatted), 19, "format should be 19 chars (XXX-XXX-XXX-XXX-XXX)");

    printf("(%s) ", formatted);
    PASS();
}

static void test_format_full(void) {
    TEST("format full (21 digits)");

    const char *pubkey = "0000000000000000000000000000000000000000000000000000000000000000";
    mobi_t m;
    char formatted[32];

    mobi_derive(pubkey, &m);
    mobi_error_t err = mobi_format_full(&m, formatted);

    ASSERT_EQ(err, MOBI_OK, "format failed");
    ASSERT_EQ(strlen(formatted), 27, "format should be 27 chars (XXX-XXX-XXX-XXX-XXX-XXX-XXX)");

    printf("(%s) ", formatted);
    PASS();
}

/* ============================================================================
 * NORMALIZATION TESTS
 * ============================================================================ */

static void test_normalize_with_hyphens(void) {
    TEST("normalize with hyphens");

    char normalized[24];
    int len = mobi_normalize("650-073-047-435", normalized, sizeof(normalized));

    ASSERT_EQ(len, 12, "should extract 12 digits");
    ASSERT_STR_EQ(normalized, "650073047435", "should strip hyphens");

    PASS();
}

static void test_normalize_with_spaces(void) {
    TEST("normalize with spaces");

    char normalized[24];
    int len = mobi_normalize("650 073 047 435", normalized, sizeof(normalized));

    ASSERT_EQ(len, 12, "should extract 12 digits");
    ASSERT_STR_EQ(normalized, "650073047435", "should strip spaces");

    PASS();
}

static void test_normalize_full_21(void) {
    TEST("normalize 21-digit with hyphens");

    char normalized[24];
    int len = mobi_normalize("650-073-047-435-892-761-234", normalized, sizeof(normalized));

    ASSERT_EQ(len, 21, "should extract 21 digits");
    ASSERT_STR_EQ(normalized, "650073047435892761234", "should strip all hyphens");

    PASS();
}

static void test_normalize_parentheses(void) {
    TEST("normalize with parentheses (phone style)");

    char normalized[24];
    int len = mobi_normalize("(650) 073-047-435", normalized, sizeof(normalized));

    ASSERT_EQ(len, 12, "should extract 12 digits");
    ASSERT_STR_EQ(normalized, "650073047435", "should strip all formatting");

    PASS();
}

/* ============================================================================
 * VALIDATION TESTS
 * ============================================================================ */

static void test_validate_12(void) {
    TEST("validate 12-digit mobi");

    ASSERT_EQ(mobi_validate("650073047435"), 1, "12 digits should be valid");
    ASSERT_EQ(mobi_validate("000000000000"), 1, "all zeros should be valid");
    ASSERT_EQ(mobi_validate("999999999999"), 1, "all nines should be valid");

    PASS();
}

static void test_validate_15(void) {
    TEST("validate 15-digit mobi");

    ASSERT_EQ(mobi_validate("650073047435892"), 1, "15 digits should be valid");

    PASS();
}

static void test_validate_18(void) {
    TEST("validate 18-digit mobi");

    ASSERT_EQ(mobi_validate("650073047435892761"), 1, "18 digits should be valid");

    PASS();
}

static void test_validate_21(void) {
    TEST("validate 21-digit mobi");

    ASSERT_EQ(mobi_validate("650073047435892761234"), 1, "21 digits should be valid");

    PASS();
}

static void test_validate_invalid(void) {
    TEST("validate rejects invalid");

    ASSERT_EQ(mobi_validate("6500730474"), 0, "10 digits should be invalid");
    ASSERT_EQ(mobi_validate("65007304743512345678901234567"), 0, "too long should be invalid");
    ASSERT_EQ(mobi_validate("650-073-047-435"), 0, "formatted should be invalid");
    ASSERT_EQ(mobi_validate("65007304743a"), 0, "with letter should be invalid");
    ASSERT_EQ(mobi_validate(NULL), 0, "null should be invalid");

    PASS();
}

/* ============================================================================
 * COMPARISON TESTS
 * ============================================================================ */

static void test_display_matches(void) {
    TEST("display_matches compares first 12 digits");

    ASSERT_EQ(mobi_display_matches("650073047435", "650073047435"), 1, "same should match");
    ASSERT_EQ(mobi_display_matches("650073047435892", "650073047435761"), 1, "same prefix should match");
    ASSERT_EQ(mobi_display_matches("650073047435892761234", "650073047435999999999"), 1, "21-digit same prefix should match");
    ASSERT_EQ(mobi_display_matches("650073047435", "650073047436"), 0, "different should not match");

    PASS();
}

static void test_full_matches(void) {
    TEST("full_matches compares all 21 digits");

    const char *pk1 = "0000000000000000000000000000000000000000000000000000000000000000";
    const char *pk2 = "0000000000000000000000000000000000000000000000000000000000000001";
    mobi_t m1, m2, m3;

    mobi_derive(pk1, &m1);
    mobi_derive(pk1, &m2);
    mobi_derive(pk2, &m3);

    ASSERT_EQ(mobi_full_matches(&m1, &m2), 1, "same pubkey should match");
    ASSERT_EQ(mobi_full_matches(&m1, &m3), 0, "different pubkeys should not match");

    PASS();
}

/* ============================================================================
 * UTILITY TESTS
 * ============================================================================ */

static void test_strerror(void) {
    TEST("strerror returns messages");

    ASSERT(strlen(mobi_strerror(MOBI_OK)) > 0, "OK should have message");
    ASSERT(strlen(mobi_strerror(MOBI_ERR_NULL)) > 0, "NULL should have message");
    ASSERT(strlen(mobi_strerror(MOBI_ERR_INVALID_HEX)) > 0, "INVALID_HEX should have message");
    ASSERT(strlen(mobi_strerror(MOBI_ERR_INVALID_LEN)) > 0, "INVALID_LEN should have message");
    ASSERT(strlen(mobi_strerror(-99)) > 0, "unknown should have message");

    PASS();
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

int main(void) {
    printf("Mobi Protocol Test Suite\n");
    printf("==========================\n\n");

    printf("Derivation tests:\n");
    test_derive_all_zeros();
    test_derive_abandon_mnemonic();
    test_derive_deterministic();
    test_derive_different_pubkeys();
    test_derive_invalid_hex();
    test_derive_invalid_length();
    test_derive_null_ptr();

    printf("\nFormatting tests:\n");
    test_format_display();
    test_format_extended();
    test_format_full();

    printf("\nNormalization tests:\n");
    test_normalize_with_hyphens();
    test_normalize_with_spaces();
    test_normalize_full_21();
    test_normalize_parentheses();

    printf("\nValidation tests:\n");
    test_validate_12();
    test_validate_15();
    test_validate_18();
    test_validate_21();
    test_validate_invalid();

    printf("\nComparison tests:\n");
    test_display_matches();
    test_full_matches();

    printf("\nUtility tests:\n");
    test_strerror();

    printf("\n==========================\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
