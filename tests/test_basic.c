/****
 *
 * Sauron Basic Test Suite
 * Tests core scoring operations
 *
 * Copyright (c) 2024-2026, Ron Dilley
 *
 ****/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include "../include/sauron.h"

#define TEST(name) printf("Testing %s... ", name)
#define PASS() printf("PASS\n")
#define FAIL(msg) do { printf("FAIL: %s\n", msg); exit(1); } while(0)

int main(void)
{
    sauron_ctx_t *ctx;
    int16_t score;
    int ret;

    printf("Sauron Basic Test Suite v%s\n\n", sauron_version());

    /* Test context creation */
    TEST("sauron_create");
    ctx = sauron_create();
    if (ctx == NULL) FAIL("returned NULL");
    PASS();

    /* Test initial statistics */
    TEST("initial statistics");
    if (sauron_count(ctx) != 0) FAIL("count not 0");
    if (sauron_block_count(ctx) != 0) FAIL("block_count not 0");
    if (sauron_memory_usage(ctx) < 2000000) FAIL("memory too low");
    PASS();

    /* Test IP parsing */
    TEST("sauron_ip_to_u32");
    if (sauron_ip_to_u32("192.168.1.1") != 0xC0A80101) FAIL("192.168.1.1");
    if (sauron_ip_to_u32("10.0.0.1") != 0x0A000001) FAIL("10.0.0.1");
    if (sauron_ip_to_u32("255.255.255.255") != 0xFFFFFFFF) FAIL("255.255.255.255");
    if (sauron_ip_to_u32("invalid") != 0) FAIL("invalid should return 0");
    if (sauron_ip_to_u32("256.1.1.1") != 0) FAIL("256.1.1.1 should return 0");
    PASS();

    /* Test set/get operations */
    TEST("set/get operations");
    score = sauron_set(ctx, "192.168.1.100", 50);
    if (score != 0) FAIL("set should return old value (0)");
    score = sauron_get(ctx, "192.168.1.100");
    if (score != 50) FAIL("get should return 50");
    PASS();

    /* Test increment */
    TEST("increment operation");
    score = sauron_incr(ctx, "192.168.1.100", 10);
    if (score != 60) FAIL("incr should return new value (60)");
    score = sauron_get(ctx, "192.168.1.100");
    if (score != 60) FAIL("get should return 60");
    PASS();

    /* Test decrement */
    TEST("decrement operation");
    score = sauron_decr(ctx, "192.168.1.100", 20);
    if (score != 40) FAIL("decr should return new value (40)");
    PASS();

    /* Test saturation (positive) */
    TEST("saturation (positive)");
    sauron_set(ctx, "192.168.1.101", 32760);
    score = sauron_incr(ctx, "192.168.1.101", 100);
    if (score != 32767) FAIL("should saturate at 32767");
    PASS();

    /* Test saturation (negative) */
    TEST("saturation (negative)");
    sauron_set(ctx, "192.168.1.102", -32760);
    score = sauron_incr(ctx, "192.168.1.102", -100);
    if (score != -32767) FAIL("should saturate at -32767");
    PASS();

    /* Test delete */
    TEST("delete operation");
    ret = sauron_delete(ctx, "192.168.1.100");
    if (ret != SAURON_OK) FAIL("delete should return OK");
    score = sauron_get(ctx, "192.168.1.100");
    if (score != 0) FAIL("get after delete should return 0");
    PASS();

    /* Test statistics after operations */
    TEST("statistics after operations");
    if (sauron_count(ctx) != 2) FAIL("count should be 2");
    if (sauron_block_count(ctx) != 1) FAIL("block_count should be 1");
    PASS();

    /* Test multiple /24 blocks */
    TEST("multiple /24 blocks");
    sauron_set(ctx, "10.0.0.1", 100);
    sauron_set(ctx, "10.0.1.1", 200);
    sauron_set(ctx, "10.1.0.1", 300);
    if (sauron_get(ctx, "10.0.0.1") != 100) FAIL("10.0.0.1 should be 100");
    if (sauron_get(ctx, "10.0.1.1") != 200) FAIL("10.0.1.1 should be 200");
    if (sauron_get(ctx, "10.1.0.1") != 300) FAIL("10.1.0.1 should be 300");
    PASS();

    /* Test u32 operations */
    TEST("u32 operations");
    uint32_t ip = sauron_ip_to_u32("172.16.0.50");
    sauron_set_u32(ctx, ip, 500);
    if (sauron_get_u32(ctx, ip) != 500) FAIL("u32 get should return 500");
    sauron_incr_u32(ctx, ip, -200);
    if (sauron_get_u32(ctx, ip) != 300) FAIL("u32 after decr should be 300");
    PASS();

    TEST("decay operation");
    sauron_set(ctx, "192.168.2.1", 1000);
    sauron_set(ctx, "192.168.2.2", -1000);
    sauron_set(ctx, "192.168.2.3", 5);
    uint64_t modified = sauron_decay(ctx, 0.5f, 10);
    score = sauron_get(ctx, "192.168.2.1");
    if (score != 500) FAIL("1000 * 0.5 should be 500");
    score = sauron_get(ctx, "192.168.2.2");
    if (score != -500) FAIL("-1000 * 0.5 should be -500");
    score = sauron_get(ctx, "192.168.2.3");
    if (score != 0) FAIL("5 * 0.5 = 2 should be deleted (deadzone=10)");
    if (modified < 3) FAIL("should modify at least 3 scores");
    PASS();

    /* Test decay with deadzone */
    TEST("decay deadzone");
    sauron_set(ctx, "192.168.3.1", 20);  /* Will become 10 after 0.5 decay */
    modified = sauron_decay(ctx, 0.5f, 10);
    score = sauron_get(ctx, "192.168.3.1");
    if (score != 0) FAIL("10 should be deleted (within deadzone=10)");
    PASS();

    /* Test save/load operations */
    TEST("save to file");
    sauron_set(ctx, "192.168.10.1", 100);
    sauron_set(ctx, "192.168.10.2", -200);
    sauron_set(ctx, "10.20.30.40", 500);
    ret = sauron_save(ctx, "/tmp/sauron_test.dat");
    if (ret != SAURON_OK) FAIL("save should return OK");
    PASS();

    /* Create a new context and load */
    TEST("load from file");
    sauron_ctx_t *ctx2 = sauron_create();
    if (ctx2 == NULL) FAIL("failed to create ctx2");
    ret = sauron_load(ctx2, "/tmp/sauron_test.dat");
    if (ret != SAURON_OK) FAIL("load should return OK");
    PASS();

    /* Verify loaded data */
    TEST("verify loaded data");
    score = sauron_get(ctx2, "192.168.10.1");
    if (score != 100) FAIL("192.168.10.1 should be 100");
    score = sauron_get(ctx2, "192.168.10.2");
    if (score != -200) FAIL("192.168.10.2 should be -200");
    score = sauron_get(ctx2, "10.20.30.40");
    if (score != 500) FAIL("10.20.30.40 should be 500");
    PASS();

    /* Test load non-existent file */
    TEST("load non-existent file");
    sauron_ctx_t *ctx3 = sauron_create();
    ret = sauron_load(ctx3, "/tmp/nonexistent_sauron.dat");
    if (ret == SAURON_OK) FAIL("load should fail for non-existent file");
    sauron_destroy(ctx3);
    PASS();

    /* Cleanup test file */
    unlink("/tmp/sauron_test.dat");

    /* Cleanup */
    TEST("sauron_destroy");
    sauron_destroy(ctx);
    sauron_destroy(ctx2);
    PASS();

    printf("\nAll tests passed!\n");
    return 0;
}
