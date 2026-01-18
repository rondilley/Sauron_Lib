/****
 *
 * Sauron Edge Case Test Suite
 * Tests boundary conditions, error paths, and corner cases
 *
 * Copyright (c) 2024-2026, Ron Dilley
 *
 ****/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include "../include/sauron.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  %-50s ", name); \
    fflush(stdout); \
} while(0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)

/* IP Parsing Edge Cases */

static void test_ip_parsing_valid(void)
{
    printf("\nIP Parsing - Valid Inputs\n");
    printf("-" "-------------------------------------------------\n");

    TEST("0.0.0.0");
    if (sauron_ip_to_u32("0.0.0.0") == 0x00000000) PASS(); else FAIL("wrong value");

    TEST("255.255.255.255");
    if (sauron_ip_to_u32("255.255.255.255") == 0xFFFFFFFF) PASS(); else FAIL("wrong value");

    TEST("1.2.3.4");
    if (sauron_ip_to_u32("1.2.3.4") == 0x01020304) PASS(); else FAIL("wrong value");

    TEST("192.168.0.1");
    if (sauron_ip_to_u32("192.168.0.1") == 0xC0A80001) PASS(); else FAIL("wrong value");

    TEST("10.0.0.0");
    if (sauron_ip_to_u32("10.0.0.0") == 0x0A000000) PASS(); else FAIL("wrong value");

    TEST("172.16.0.0");
    if (sauron_ip_to_u32("172.16.0.0") == 0xAC100000) PASS(); else FAIL("wrong value");

    TEST("Leading zeros: 001.002.003.004");
    /* Leading zeros should still parse correctly */
    uint32_t ip = sauron_ip_to_u32("001.002.003.004");
    if (ip == 0x01020304) PASS(); else FAIL("wrong value");
}

static void test_ip_parsing_invalid(void)
{
    printf("\nIP Parsing - Invalid Inputs\n");
    printf("-" "-------------------------------------------------\n");

    TEST("Empty string");
    if (sauron_ip_to_u32("") == 0) PASS(); else FAIL("should return 0");

    TEST("NULL pointer");
    if (sauron_ip_to_u32(NULL) == 0) PASS(); else FAIL("should return 0");

    TEST("256.0.0.0 (octet > 255)");
    if (sauron_ip_to_u32("256.0.0.0") == 0) PASS(); else FAIL("should return 0");

    TEST("0.256.0.0");
    if (sauron_ip_to_u32("0.256.0.0") == 0) PASS(); else FAIL("should return 0");

    TEST("0.0.256.0");
    if (sauron_ip_to_u32("0.0.256.0") == 0) PASS(); else FAIL("should return 0");

    TEST("0.0.0.256");
    if (sauron_ip_to_u32("0.0.0.256") == 0) PASS(); else FAIL("should return 0");

    TEST("-1.0.0.0 (negative)");
    if (sauron_ip_to_u32("-1.0.0.0") == 0) PASS(); else FAIL("should return 0");

    TEST("1.2.3 (only 3 octets)");
    if (sauron_ip_to_u32("1.2.3") == 0) PASS(); else FAIL("should return 0");

    TEST("1.2.3.4.5 (5 octets)");
    if (sauron_ip_to_u32("1.2.3.4.5") == 0) PASS(); else FAIL("should return 0");

    TEST("a.b.c.d (letters)");
    if (sauron_ip_to_u32("a.b.c.d") == 0) PASS(); else FAIL("should return 0");

    TEST("1.2.3.4x (trailing chars)");
    /* This might parse as 1.2.3.4 - check behavior */
    uint32_t ip = sauron_ip_to_u32("1.2.3.4x");
    if (ip == 0 || ip == 0x01020304) PASS(); else FAIL("unexpected value");

    TEST("192.168.1 (missing octet)");
    if (sauron_ip_to_u32("192.168.1") == 0) PASS(); else FAIL("should return 0");

    TEST("192..168.1 (empty octet)");
    uint32_t double_dot = sauron_ip_to_u32("192..168.1");
    if (double_dot == 0) PASS(); else FAIL("should reject empty octet");

    TEST(".192.168.1.1 (leading dot)");
    if (sauron_ip_to_u32(".192.168.1.1") == 0) PASS(); else FAIL("should return 0");

    TEST("192.168.1.1. (trailing dot)");
    if (sauron_ip_to_u32("192.168.1.1.") == 0) PASS(); else FAIL("should return 0");

    TEST("1000.0.0.0 (4 digit octet)");
    if (sauron_ip_to_u32("1000.0.0.0") == 0) PASS(); else FAIL("should return 0");

    TEST("spaces: \" 192.168.1.1\"");
    if (sauron_ip_to_u32(" 192.168.1.1") == 0) PASS(); else FAIL("should return 0");

    TEST("localhost");
    if (sauron_ip_to_u32("localhost") == 0) PASS(); else FAIL("should return 0");
}

/* Score Boundary Tests */

static void test_score_boundaries(void)
{
    printf("\nScore Boundary Tests\n");
    printf("-" "-------------------------------------------------\n");

    sauron_ctx_t *ctx = sauron_create();
    if (!ctx) {
        printf("  FAIL: Could not create context\n");
        return;
    }

    int16_t score;

    /* Maximum positive */
    TEST("Set to INT16_MAX (32767)");
    sauron_set(ctx, "10.0.0.1", 32767);
    score = sauron_get(ctx, "10.0.0.1");
    if (score == 32767) PASS(); else FAIL("wrong value");

    /* Minimum negative (note: -32768 is not used, -32767 is min) */
    TEST("Set to -32767");
    sauron_set(ctx, "10.0.0.2", -32767);
    score = sauron_get(ctx, "10.0.0.2");
    if (score == -32767) PASS(); else FAIL("wrong value");

    /* Saturation at positive boundary */
    TEST("Increment past 32767 saturates");
    sauron_set(ctx, "10.0.0.3", 32760);
    score = sauron_incr(ctx, "10.0.0.3", 100);
    if (score == 32767) PASS(); else FAIL("should saturate at 32767");

    /* Saturation at negative boundary */
    TEST("Decrement past -32767 saturates");
    sauron_set(ctx, "10.0.0.4", -32760);
    score = sauron_incr(ctx, "10.0.0.4", -100);
    if (score == -32767) PASS(); else FAIL("should saturate at -32767");

    /* Large positive increment from 0 */
    TEST("Large increment from 0");
    score = sauron_incr(ctx, "10.0.0.5", 30000);
    if (score == 30000) PASS(); else FAIL("wrong value");

    /* Large negative increment from 0 */
    TEST("Large decrement from 0");
    score = sauron_incr(ctx, "10.0.0.6", -30000);
    if (score == -30000) PASS(); else FAIL("wrong value");

    /* Overflow test: max + 1 */
    TEST("32767 + 1 = 32767 (saturate)");
    sauron_set(ctx, "10.0.0.7", 32767);
    score = sauron_incr(ctx, "10.0.0.7", 1);
    if (score == 32767) PASS(); else FAIL("should saturate");

    /* Underflow test: min - 1 */
    TEST("-32767 - 1 = -32767 (saturate)");
    sauron_set(ctx, "10.0.0.8", -32767);
    score = sauron_incr(ctx, "10.0.0.8", -1);
    if (score == -32767) PASS(); else FAIL("should saturate");

    /* Zero handling */
    TEST("Set to 0 effectively deletes");
    sauron_set(ctx, "10.0.0.9", 100);
    sauron_set(ctx, "10.0.0.9", 0);
    score = sauron_get(ctx, "10.0.0.9");
    if (score == 0) PASS(); else FAIL("should be 0");

    /* Increment on non-existent IP */
    TEST("Increment non-existent IP");
    score = sauron_incr(ctx, "10.0.0.10", 50);
    if (score == 50) PASS(); else FAIL("should be 50");

    /* Decrement to zero */
    TEST("Decrement to exactly zero");
    sauron_set(ctx, "10.0.0.11", 100);
    score = sauron_decr(ctx, "10.0.0.11", 100);
    if (score == 0) PASS(); else FAIL("should be 0");

    /* Decrement past zero */
    TEST("Decrement past zero goes negative");
    sauron_set(ctx, "10.0.0.12", 50);
    score = sauron_decr(ctx, "10.0.0.12", 100);
    if (score == -50) PASS(); else FAIL("should be -50");

    sauron_destroy(ctx);
}

/* NULL and Invalid Argument Tests */

static void test_null_handling(void)
{
    printf("\nNULL and Invalid Argument Handling\n");
    printf("-" "-------------------------------------------------\n");

    sauron_ctx_t *ctx = sauron_create();

    /* NULL context tests */
    TEST("sauron_get with NULL context");
    int16_t score = sauron_get(NULL, "10.0.0.1");
    if (score == 0) PASS(); else FAIL("should return 0");

    TEST("sauron_set with NULL context");
    score = sauron_set(NULL, "10.0.0.1", 100);
    if (score == 0) PASS(); else FAIL("should return 0");

    TEST("sauron_incr with NULL context");
    score = sauron_incr(NULL, "10.0.0.1", 10);
    if (score == 0) PASS(); else FAIL("should return 0");

    TEST("sauron_delete with NULL context");
    int ret = sauron_delete(NULL, "10.0.0.1");
    if (ret != SAURON_OK) PASS(); else FAIL("should return error");

    TEST("sauron_count with NULL context");
    uint64_t count = sauron_count(NULL);
    if (count == 0) PASS(); else FAIL("should return 0");

    TEST("sauron_destroy with NULL context");
    sauron_destroy(NULL);  /* Should not crash */
    PASS();

    /* NULL IP string tests */
    TEST("sauron_get with NULL IP");
    score = sauron_get(ctx, NULL);
    if (score == 0) PASS(); else FAIL("should return 0");

    TEST("sauron_set with NULL IP");
    score = sauron_set(ctx, NULL, 100);
    if (score == 0) PASS(); else FAIL("should return 0");

    /* Invalid IP tests */
    TEST("Operations on invalid IP string");
    score = sauron_set(ctx, "not-an-ip", 100);
    if (score == 0) PASS(); else FAIL("should return 0");

    TEST("Get on invalid IP returns 0");
    score = sauron_get(ctx, "invalid");
    if (score == 0) PASS(); else FAIL("should return 0");

    sauron_destroy(ctx);
}

/* Decay Edge Cases */

static void test_decay_edge_cases(void)
{
    printf("\nDecay Edge Cases\n");
    printf("-" "-------------------------------------------------\n");

    sauron_ctx_t *ctx = sauron_create();

    /* Decay on empty context */
    TEST("Decay on empty context");
    uint64_t modified = sauron_decay(ctx, 0.5f, 10);
    if (modified == 0) PASS(); else FAIL("should modify 0");

    /* Populate with test data */
    sauron_set(ctx, "10.0.0.1", 100);
    sauron_set(ctx, "10.0.0.2", -100);
    sauron_set(ctx, "10.0.0.3", 20);
    sauron_set(ctx, "10.0.0.4", -20);
    sauron_set(ctx, "10.0.0.5", 1);

    /* Decay factor = 1.0 (no change) */
    TEST("Decay factor 1.0 (no change)");
    modified = sauron_decay(ctx, 1.0f, 0);
    int16_t score = sauron_get(ctx, "10.0.0.1");
    if (score == 100) PASS(); else FAIL("score should be unchanged");

    /* Decay factor = 0.0 (all become 0) */
    TEST("Decay factor 0.0 (all zero)");
    sauron_set(ctx, "10.0.1.1", 1000);
    modified = sauron_decay(ctx, 0.0f, 0);
    score = sauron_get(ctx, "10.0.1.1");
    if (score == 0) PASS(); else FAIL("score should be 0");

    /* Deadzone tests */
    TEST("Deadzone removes small scores");
    sauron_set(ctx, "10.0.2.1", 5);
    sauron_set(ctx, "10.0.2.2", -5);
    sauron_set(ctx, "10.0.2.3", 100);
    sauron_decay(ctx, 1.0f, 10);  /* Deadzone of 10 */
    if (sauron_get(ctx, "10.0.2.1") == 0 &&
        sauron_get(ctx, "10.0.2.2") == 0 &&
        sauron_get(ctx, "10.0.2.3") == 100) PASS();
    else FAIL("deadzone not applied correctly");

    /* Decay with NULL context */
    TEST("Decay with NULL context");
    modified = sauron_decay(NULL, 0.5f, 10);
    if (modified == 0) PASS(); else FAIL("should return 0");

    /* Multiple decays */
    TEST("Multiple successive decays");
    sauron_set(ctx, "10.0.3.1", 1000);
    sauron_decay(ctx, 0.5f, 0);  /* 500 */
    sauron_decay(ctx, 0.5f, 0);  /* 250 */
    sauron_decay(ctx, 0.5f, 0);  /* 125 */
    score = sauron_get(ctx, "10.0.3.1");
    if (score == 125) PASS(); else FAIL("expected 125");

    /* Decay negative scores */
    TEST("Decay negative scores");
    sauron_set(ctx, "10.0.4.1", -1000);
    sauron_decay(ctx, 0.5f, 0);
    score = sauron_get(ctx, "10.0.4.1");
    if (score == -500) PASS(); else FAIL("expected -500");

    sauron_destroy(ctx);
}

/* Archive Edge Cases */

static void test_archive_edge_cases(void)
{
    printf("\nArchive Edge Cases\n");
    printf("-" "-------------------------------------------------\n");

    sauron_ctx_t *ctx = sauron_create();
    int ret;

    /* Save empty context */
    TEST("Save empty context");
    ret = sauron_save(ctx, "/tmp/sauron_empty.dat");
    if (ret == SAURON_OK) PASS(); else FAIL("save failed");

    /* Load empty archive */
    TEST("Load empty archive");
    sauron_ctx_t *ctx2 = sauron_create();
    ret = sauron_load(ctx2, "/tmp/sauron_empty.dat");
    if (ret == SAURON_OK && sauron_count(ctx2) == 0) PASS(); else FAIL("load failed");
    sauron_destroy(ctx2);

    /* Save with NULL context */
    TEST("Save with NULL context");
    ret = sauron_save(NULL, "/tmp/sauron_null.dat");
    if (ret != SAURON_OK) PASS(); else FAIL("should fail");

    /* Save with NULL filename */
    TEST("Save with NULL filename");
    ret = sauron_save(ctx, NULL);
    if (ret != SAURON_OK) PASS(); else FAIL("should fail");

    /* Load with NULL context */
    TEST("Load with NULL context");
    ret = sauron_load(NULL, "/tmp/sauron_empty.dat");
    if (ret != SAURON_OK) PASS(); else FAIL("should fail");

    /* Load with NULL filename */
    TEST("Load with NULL filename");
    ret = sauron_load(ctx, NULL);
    if (ret != SAURON_OK) PASS(); else FAIL("should fail");

    /* Load non-existent file */
    TEST("Load non-existent file");
    ret = sauron_load(ctx, "/nonexistent/path/file.dat");
    if (ret != SAURON_OK) PASS(); else FAIL("should fail");

    /* Save to non-writable path */
    TEST("Save to non-writable path");
    ret = sauron_save(ctx, "/nonexistent/path/file.dat");
    if (ret != SAURON_OK) PASS(); else FAIL("should fail");

    /* Save and verify data integrity */
    TEST("Save/load data integrity");
    sauron_set(ctx, "192.168.1.1", 12345);
    sauron_set(ctx, "192.168.1.2", -12345);
    sauron_set(ctx, "10.0.0.1", 32767);
    sauron_set(ctx, "10.0.0.2", -32767);
    sauron_save(ctx, "/tmp/sauron_integrity.dat");

    ctx2 = sauron_create();
    sauron_load(ctx2, "/tmp/sauron_integrity.dat");
    if (sauron_get(ctx2, "192.168.1.1") == 12345 &&
        sauron_get(ctx2, "192.168.1.2") == -12345 &&
        sauron_get(ctx2, "10.0.0.1") == 32767 &&
        sauron_get(ctx2, "10.0.0.2") == -32767) PASS();
    else FAIL("data mismatch");
    sauron_destroy(ctx2);

    /* Load clears existing data */
    TEST("Load clears existing data");
    ctx2 = sauron_create();
    sauron_set(ctx2, "172.16.0.1", 999);  /* Should be cleared */
    sauron_load(ctx2, "/tmp/sauron_integrity.dat");
    if (sauron_get(ctx2, "172.16.0.1") == 0) PASS(); else FAIL("old data not cleared");
    sauron_destroy(ctx2);

    /* Cleanup */
    unlink("/tmp/sauron_empty.dat");
    unlink("/tmp/sauron_integrity.dat");

    sauron_destroy(ctx);
}

/* Statistics Edge Cases */

static void test_statistics_edge_cases(void)
{
    printf("\nStatistics Edge Cases\n");
    printf("-" "-------------------------------------------------\n");

    sauron_ctx_t *ctx = sauron_create();

    TEST("Initial count is 0");
    if (sauron_count(ctx) == 0) PASS(); else FAIL("should be 0");

    TEST("Initial block_count is 0");
    if (sauron_block_count(ctx) == 0) PASS(); else FAIL("should be 0");

    TEST("Initial memory > 0 (bitmap)");
    if (sauron_memory_usage(ctx) > 0) PASS(); else FAIL("should be > 0");

    /* Add and remove, check count */
    TEST("Count after add/delete");
    sauron_set(ctx, "10.0.0.1", 100);
    sauron_set(ctx, "10.0.0.2", 200);
    if (sauron_count(ctx) != 2) { FAIL("count should be 2"); }
    else {
        sauron_delete(ctx, "10.0.0.1");
        if (sauron_count(ctx) == 1) PASS(); else FAIL("count should be 1");
    }

    /* Block count with multiple /24s */
    TEST("Block count across /24s");
    sauron_set(ctx, "10.1.0.1", 100);
    sauron_set(ctx, "10.2.0.1", 100);
    sauron_set(ctx, "10.3.0.1", 100);
    uint64_t blocks = sauron_block_count(ctx);
    if (blocks >= 4) PASS(); else FAIL("should have at least 4 blocks");

    /* Memory grows with blocks */
    TEST("Memory increases with blocks");
    size_t mem1 = sauron_memory_usage(ctx);
    sauron_set(ctx, "172.16.0.1", 100);
    sauron_set(ctx, "172.17.0.1", 100);
    size_t mem2 = sauron_memory_usage(ctx);
    if (mem2 > mem1) PASS(); else FAIL("memory should increase");

    sauron_destroy(ctx);
}

/* u32 API Consistency */

static void test_u32_consistency(void)
{
    printf("\nString/u32 API Consistency\n");
    printf("-" "-------------------------------------------------\n");

    sauron_ctx_t *ctx = sauron_create();

    /* Set via string, get via u32 */
    TEST("Set string, get u32");
    sauron_set(ctx, "192.168.1.100", 500);
    uint32_t ip = sauron_ip_to_u32("192.168.1.100");
    if (sauron_get_u32(ctx, ip) == 500) PASS(); else FAIL("mismatch");

    /* Set via u32, get via string */
    TEST("Set u32, get string");
    ip = sauron_ip_to_u32("192.168.1.101");
    sauron_set_u32(ctx, ip, 600);
    if (sauron_get(ctx, "192.168.1.101") == 600) PASS(); else FAIL("mismatch");

    /* Increment via string, verify via u32 */
    TEST("Incr string, verify u32");
    sauron_incr(ctx, "192.168.1.100", 100);
    ip = sauron_ip_to_u32("192.168.1.100");
    if (sauron_get_u32(ctx, ip) == 600) PASS(); else FAIL("mismatch");

    /* Increment via u32, verify via string */
    TEST("Incr u32, verify string");
    ip = sauron_ip_to_u32("192.168.1.101");
    sauron_incr_u32(ctx, ip, 100);
    if (sauron_get(ctx, "192.168.1.101") == 700) PASS(); else FAIL("mismatch");

    /* Delete via u32, verify via string */
    TEST("Delete u32, verify string");
    ip = sauron_ip_to_u32("192.168.1.100");
    sauron_delete_u32(ctx, ip);
    if (sauron_get(ctx, "192.168.1.100") == 0) PASS(); else FAIL("should be 0");

    /* Delete via string, verify via u32 */
    TEST("Delete string, verify u32");
    sauron_delete(ctx, "192.168.1.101");
    ip = sauron_ip_to_u32("192.168.1.101");
    if (sauron_get_u32(ctx, ip) == 0) PASS(); else FAIL("should be 0");

    sauron_destroy(ctx);
}

static void test_new_apis(void)
{
    printf("\nNew API Tests\n");
    printf("-" "-------------------------------------------------\n");

    sauron_ctx_t *ctx = sauron_create();

    TEST("sauron_clear on populated context");
    sauron_set(ctx, "10.0.0.1", 100);
    sauron_set(ctx, "10.0.0.2", 200);
    sauron_set(ctx, "10.0.0.3", 300);
    int ret = sauron_clear(ctx);
    if (ret == SAURON_OK && sauron_count(ctx) == 0) PASS();
    else FAIL("clear failed");

    TEST("sauron_clear with NULL context");
    ret = sauron_clear(NULL);
    if (ret != SAURON_OK) PASS(); else FAIL("should return error");

    TEST("Get after clear returns 0");
    if (sauron_get(ctx, "10.0.0.1") == 0) PASS(); else FAIL("should be 0");

    TEST("sauron_get_ex finds existing score");
    sauron_set(ctx, "10.0.0.1", 100);
    int16_t score_out;
    ret = sauron_get_ex(ctx, sauron_ip_to_u32("10.0.0.1"), &score_out);
    if (ret == SAURON_OK && score_out == 100) PASS();
    else FAIL("should find score");

    TEST("sauron_get_ex returns error for not found");
    ret = sauron_get_ex(ctx, sauron_ip_to_u32("10.0.0.99"), &score_out);
    if (ret == SAURON_ERR_INVALID) PASS(); else FAIL("should return INVALID");

    TEST("sauron_get_ex with NULL score_out");
    ret = sauron_get_ex(ctx, sauron_ip_to_u32("10.0.0.1"), NULL);
    if (ret == SAURON_ERR_NULL) PASS(); else FAIL("should return NULL error");

    char buf[32];
    TEST("sauron_u32_to_ip_s normal case");
    int len = sauron_u32_to_ip_s(0xC0A80001, buf, sizeof(buf));
    if (len > 0 && strcmp(buf, "192.168.0.1") == 0) PASS();
    else FAIL("unexpected result");

    TEST("sauron_u32_to_ip_s with small buffer");
    len = sauron_u32_to_ip_s(0xC0A80001, buf, 8);  /* Too small */
    if (len == 0) PASS(); else FAIL("should fail with small buffer");

    TEST("sauron_u32_to_ip_s with NULL buffer");
    len = sauron_u32_to_ip_s(0xC0A80001, NULL, 16);
    if (len == 0) PASS(); else FAIL("should fail with NULL buffer");

    sauron_clear(ctx);
    sauron_set(ctx, "10.0.0.1", 100);
    sauron_set(ctx, "10.0.0.2", 200);
    sauron_set(ctx, "10.0.0.3", 300);

    TEST("sauron_foreach with NULL context");
    uint64_t count = sauron_foreach(NULL, NULL, NULL);
    if (count == 0) PASS(); else FAIL("should return 0");

    TEST("sauron_foreach with NULL callback");
    count = sauron_foreach(ctx, NULL, NULL);
    if (count == 0) PASS(); else FAIL("should return 0");

    sauron_destroy(ctx);
}

/* Callback for foreach test */
static int foreach_counter(uint32_t ip, int16_t score, void *user_data)
{
    (void)ip;
    (void)score;
    int *counter = (int *)user_data;
    (*counter)++;
    return 0;  /* Continue */
}

static int foreach_stopper(uint32_t ip, int16_t score, void *user_data)
{
    (void)ip;
    (void)score;
    int *counter = (int *)user_data;
    (*counter)++;
    if (*counter >= 2)
        return 1;  /* Stop early */
    return 0;
}

static void test_foreach_api(void)
{
    printf("\nIteration API Tests\n");
    printf("-" "-------------------------------------------------\n");

    sauron_ctx_t *ctx = sauron_create();
    int counter = 0;

    /* Populate with test data */
    sauron_set(ctx, "10.0.0.1", 100);
    sauron_set(ctx, "10.0.0.2", 200);
    sauron_set(ctx, "10.0.0.3", 300);
    sauron_set(ctx, "10.0.0.4", 400);
    sauron_set(ctx, "10.0.0.5", 500);

    TEST("sauron_foreach counts all entries");
    counter = 0;
    uint64_t iterated = sauron_foreach(ctx, foreach_counter, &counter);
    if (iterated == 5 && counter == 5) PASS();
    else FAIL("expected 5 iterations");

    TEST("sauron_foreach with early stop");
    counter = 0;
    iterated = sauron_foreach(ctx, foreach_stopper, &counter);
    if (counter == 2) PASS();  /* Stopped after 2 */
    else FAIL("should stop at 2");

    TEST("sauron_foreach on empty context");
    sauron_clear(ctx);
    counter = 0;
    iterated = sauron_foreach(ctx, foreach_counter, &counter);
    if (iterated == 0 && counter == 0) PASS();
    else FAIL("should iterate 0");

    sauron_destroy(ctx);
}

static void test_audit_fixes(void)
{
    printf("\nValidation Tests\n");
    printf("-" "-------------------------------------------------\n");

    sauron_ctx_t *ctx = sauron_create();

    TEST("decr_u32 with INT16_MIN");
    sauron_set(ctx, "10.0.0.1", 0);
    /* INT16_MIN = -32768, negating would be UB */
    /* Fix should handle this safely */
    int16_t score = sauron_decr_u32(ctx, sauron_ip_to_u32("10.0.0.1"), INT16_MIN);
    /* Result should be saturated to INT16_MAX (32767) or similar safe value */
    if (score == 32767) PASS(); else FAIL("should saturate safely");

    TEST("decr (string) with INT16_MIN");
    sauron_set(ctx, "10.0.0.2", 0);
    score = sauron_decr(ctx, "10.0.0.2", INT16_MIN);
    if (score == 32767) PASS(); else FAIL("should saturate safely");

    TEST("Decay with negative factor");
    sauron_set(ctx, "10.0.0.3", 100);
    uint64_t modified = sauron_decay(ctx, -0.5f, 0);
    if (modified == 0 && sauron_get(ctx, "10.0.0.3") == 100) PASS();
    else FAIL("negative factor should be rejected");

    TEST("Decay with factor > 1.0");
    modified = sauron_decay(ctx, 1.5f, 0);
    if (modified == 0 && sauron_get(ctx, "10.0.0.3") == 100) PASS();
    else FAIL("factor > 1.0 should be rejected");

    TEST("Decay with valid factor 0.0");
    sauron_set(ctx, "10.0.0.4", 100);
    modified = sauron_decay(ctx, 0.0f, 0);
    if (sauron_get(ctx, "10.0.0.4") == 0) PASS();
    else FAIL("factor 0.0 should be valid");

    TEST("Decay with valid factor 1.0");
    sauron_set(ctx, "10.0.0.5", 100);
    modified = sauron_decay(ctx, 1.0f, 0);
    if (sauron_get(ctx, "10.0.0.5") == 100) PASS();
    else FAIL("factor 1.0 should be valid");

    TEST("Reject leading dot");
    if (sauron_ip_to_u32(".1.2.3.4") == 0) PASS(); else FAIL("should reject");

    TEST("Reject trailing dot");
    if (sauron_ip_to_u32("1.2.3.4.") == 0) PASS(); else FAIL("should reject");

    TEST("Reject consecutive dots");
    if (sauron_ip_to_u32("1..2.3.4") == 0) PASS(); else FAIL("should reject");

    sauron_destroy(ctx);
}

/* Bulk Load Tests */

static void test_bulk_load(void)
{
    printf("\nBulk Load Tests\n");
    printf("-" "-------------------------------------------------\n");

    sauron_ctx_t *ctx = sauron_create();
    sauron_bulk_result_t result;
    int ret;
    FILE *fp;

    /* Create test file with various formats */
    TEST("Create test bulk file");
    fp = fopen("/tmp/sauron_bulk_test.csv", "w");
    if (fp == NULL) { FAIL("cannot create file"); goto cleanup; }

    /* Write test data */
    fprintf(fp, "# Comment line\n");
    fprintf(fp, "192.168.1.1,100\n");           /* Absolute set */
    fprintf(fp, "192.168.1.2, +50\n");          /* Relative positive with space */
    fprintf(fp, "192.168.1.3,-25\n");           /* Relative negative */
    fprintf(fp, "10.0.0.1, 1000\n");            /* Absolute set */
    fprintf(fp, "10.0.0.2,+500\n");             /* Relative positive */
    fprintf(fp, "\n");                           /* Empty line */
    fprintf(fp, "10.0.0.3, -100\n");            /* Relative negative with space */
    fprintf(fp, "invalid,100\n");               /* Parse error */
    fprintf(fp, "127.0.0.1,100\n");             /* Loopback (now allowed) */
    fprintf(fp, "8.8.8.8,32767\n");             /* Max value */
    fprintf(fp, "8.8.8.9,-32767\n");            /* Min value */
    fclose(fp);
    PASS();

    /* Load the bulk file */
    TEST("Bulk load from file");
    ret = sauron_bulk_load(ctx, "/tmp/sauron_bulk_test.csv", &result);
    if (ret == SAURON_OK) PASS(); else FAIL("bulk load failed");

    /* Verify statistics
     * Lines: 12 total (including comment, empty)
     * Sets: 7 (192.168.1.1=100, 192.168.1.3=-25, 10.0.0.1=1000, 10.0.0.3=-100, 127.0.0.1=100, 8.8.8.8=32767, 8.8.8.9=-32767)
     * Updates: 2 (192.168.1.2=+50, 10.0.0.2=+500)
     * Skipped: 1 (parse error)
     */
    TEST("Bulk load statistics");
    if (result.lines_processed == 12 &&
        result.sets == 7 &&
        result.updates == 2 &&
        result.parse_errors == 1 &&
        result.lines_skipped == 1) PASS();  /* 1 parse error */
    else {
        printf("FAIL: lines=%lu sets=%lu updates=%lu errors=%lu skipped=%lu\n",
               (unsigned long)result.lines_processed,
               (unsigned long)result.sets,
               (unsigned long)result.updates,
               (unsigned long)result.parse_errors,
               (unsigned long)result.lines_skipped);
    }

    /* Verify loaded data */
    TEST("Verify loaded scores");
    if (sauron_get(ctx, "192.168.1.1") == 100 &&
        sauron_get(ctx, "192.168.1.2") == 50 &&   /* +50 from 0 */
        sauron_get(ctx, "192.168.1.3") == -25 &&  /* SET to -25 */
        sauron_get(ctx, "10.0.0.1") == 1000 &&
        sauron_get(ctx, "10.0.0.2") == 500 &&     /* +500 from 0 */
        sauron_get(ctx, "10.0.0.3") == -100 &&    /* SET to -100 */
        sauron_get(ctx, "8.8.8.8") == 32767 &&
        sauron_get(ctx, "8.8.8.9") == -32767) PASS();
    else FAIL("score mismatch");

    /* Test relative update on existing score */
    TEST("Relative update on existing score");
    sauron_clear(ctx);
    sauron_set(ctx, "192.168.1.1", 100);

    fp = fopen("/tmp/sauron_bulk_update.csv", "w");
    fprintf(fp, "192.168.1.1,+50\n");    /* Should become 150 */
    fprintf(fp, "192.168.1.1,+-30\n");   /* Should become 120 (relative decrement) */
    fclose(fp);

    ret = sauron_bulk_load(ctx, "/tmp/sauron_bulk_update.csv", NULL);
    if (ret == SAURON_OK && sauron_get(ctx, "192.168.1.1") == 120) PASS();
    else FAIL("relative update failed");

    /* Test buffer-based bulk load */
    TEST("Bulk load from buffer");
    sauron_clear(ctx);
    const char *bulk_data = "10.0.0.1,100\n10.0.0.2,+200\n10.0.0.3,-50\n";
    ret = sauron_bulk_load_buffer(ctx, bulk_data, strlen(bulk_data), &result);
    if (ret == SAURON_OK && result.lines_processed == 3 &&
        sauron_get(ctx, "10.0.0.1") == 100 &&
        sauron_get(ctx, "10.0.0.2") == 200 &&
        sauron_get(ctx, "10.0.0.3") == -50) PASS();
    else FAIL("buffer load failed");

    /* Test NULL handling */
    TEST("Bulk load with NULL context");
    ret = sauron_bulk_load(NULL, "/tmp/sauron_bulk_test.csv", NULL);
    if (ret != SAURON_OK) PASS(); else FAIL("should fail");

    TEST("Bulk load with NULL filename");
    ret = sauron_bulk_load(ctx, NULL, NULL);
    if (ret != SAURON_OK) PASS(); else FAIL("should fail");

    TEST("Bulk load non-existent file");
    ret = sauron_bulk_load(ctx, "/nonexistent/file.csv", NULL);
    if (ret != SAURON_OK) PASS(); else FAIL("should fail");

    /* Test performance reporting */
    TEST("Performance metrics populated");
    ret = sauron_bulk_load(ctx, "/tmp/sauron_bulk_test.csv", &result);
    if (result.elapsed_seconds > 0.0 && result.lines_per_second > 0.0) PASS();
    else FAIL("timing not populated");

cleanup:
    unlink("/tmp/sauron_bulk_test.csv");
    unlink("/tmp/sauron_bulk_update.csv");
    sauron_destroy(ctx);
}

/* Main */

int main(void)
{
    printf("Sauron Edge Case Test Suite v%s\n", sauron_version());
    printf("=================================================\n");

    test_ip_parsing_valid();
    test_ip_parsing_invalid();
    test_score_boundaries();
    test_null_handling();
    test_decay_edge_cases();
    test_archive_edge_cases();
    test_statistics_edge_cases();
    test_u32_consistency();
    test_new_apis();
    test_foreach_api();
    test_audit_fixes();
    test_bulk_load();

    printf("\n=================================================\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);

    if (tests_passed == tests_run) {
        printf("All edge case tests passed!\n");
        return 0;
    } else {
        printf("%d test(s) FAILED!\n", tests_run - tests_passed);
        return 1;
    }
}
