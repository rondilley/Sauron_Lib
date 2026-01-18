/*
 * Sauron Library - Basic C Example
 *
 * Demonstrates core library functionality including:
 * - Context creation/destruction
 * - Score operations (get/set/incr/decr)
 * - Decay operations
 * - Persistence (save/load)
 * - Bulk loading
 * - Statistics
 *
 * Build:
 *   gcc -O2 -o example_basic example_basic.c -I../include -L../src/.libs \
 *       -lsauron -Wl,-rpath,../src/.libs
 *
 * Run:
 *   ./example_basic
 *
 * Copyright (c) 2024-2026, Ron Dilley
 */

#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sauron.h>

static double get_time(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void print_stats(sauron_ctx_t *ctx, const char *label)
{
    printf("\n--- %s ---\n", label);
    printf("  Active scores: %lu\n", (unsigned long)sauron_count(ctx));
    printf("  Blocks allocated: %lu\n", (unsigned long)sauron_block_count(ctx));
    printf("  Memory usage: %.2f KB\n", sauron_memory_usage(ctx) / 1024.0);
}

int main(void)
{
    printf("Sauron Library - Basic C Example\n");
    printf("=================================\n");
    printf("Library version: %s\n\n", sauron_version());

    /* Create scoring engine context */
    sauron_ctx_t *ctx = sauron_create();
    if (!ctx) {
        fprintf(stderr, "ERROR: Failed to create context\n");
        return 1;
    }
    printf("[OK] Created scoring engine context\n");

    print_stats(ctx, "Initial State");

    /* ------------------------------------------------------------ */
    printf("\n\n=== Basic Score Operations ===\n");
    /* ------------------------------------------------------------ */

    /* Set scores for some IPs */
    const char *test_ips[] = {
        "192.168.1.100",
        "10.0.0.50",
        "172.16.0.1",
        "8.8.8.8",
        "1.1.1.1"
    };
    int16_t test_scores[] = {100, -50, 200, 10, -10};
    size_t num_ips = sizeof(test_ips) / sizeof(test_ips[0]);

    printf("\nSetting initial scores:\n");
    for (size_t i = 0; i < num_ips; i++) {
        int16_t old = sauron_set(ctx, test_ips[i], test_scores[i]);
        printf("  %s: set to %d (was %d)\n", test_ips[i], test_scores[i], old);
    }

    /* Read back the scores */
    printf("\nReading scores:\n");
    for (size_t i = 0; i < num_ips; i++) {
        int16_t score = sauron_get(ctx, test_ips[i]);
        printf("  %s: %d\n", test_ips[i], score);
    }

    /* Increment/decrement operations */
    printf("\nIncrement/decrement operations:\n");
    int16_t new_score;

    new_score = sauron_incr(ctx, "192.168.1.100", 25);
    printf("  192.168.1.100: incr(+25) -> %d\n", new_score);

    new_score = sauron_decr(ctx, "192.168.1.100", 10);
    printf("  192.168.1.100: decr(-10) -> %d\n", new_score);

    new_score = sauron_incr(ctx, "10.0.0.50", -100);
    printf("  10.0.0.50: incr(-100) -> %d (negative delta)\n", new_score);

    print_stats(ctx, "After Basic Operations");

    /* ------------------------------------------------------------ */
    printf("\n\n=== uint32 API (Faster Path) ===\n");
    /* ------------------------------------------------------------ */

    /* Convert IP string to uint32 for faster operations */
    uint32_t ip_u32 = sauron_ip_to_u32("45.33.32.156");  /* scanme.nmap.org */
    char ip_buf[16];
    sauron_u32_to_ip(ip_u32, ip_buf);
    printf("\nUsing uint32 API for %s (0x%08x):\n", ip_buf, ip_u32);

    sauron_set_u32(ctx, ip_u32, 500);
    printf("  set_u32(500) -> score now %d\n", sauron_get_u32(ctx, ip_u32));

    sauron_incr_u32(ctx, ip_u32, 100);
    printf("  incr_u32(100) -> score now %d\n", sauron_get_u32(ctx, ip_u32));

    /* ------------------------------------------------------------ */
    printf("\n\n=== Saturation Behavior ===\n");
    /* ------------------------------------------------------------ */

    printf("\nTesting saturation at boundaries:\n");

    sauron_set(ctx, "45.33.32.1", 32000);
    new_score = sauron_incr(ctx, "45.33.32.1", 1000);
    printf("  32000 + 1000 = %d (saturates at 32767)\n", new_score);

    sauron_set(ctx, "45.33.32.2", -32000);
    new_score = sauron_decr(ctx, "45.33.32.2", 1000);
    printf("  -32000 - 1000 = %d (saturates at -32767)\n", new_score);

    /* ------------------------------------------------------------ */
    printf("\n\n=== Special IP Scoring ===\n");
    /* ------------------------------------------------------------ */

    printf("\nAll IPs can now be scored (applications handle filtering):\n");
    const char *special_ips[] = {
        "127.0.0.1",      /* Loopback */
        "0.0.0.0",        /* This network */
        "224.0.0.1",      /* Multicast */
        "255.255.255.255" /* Broadcast */
    };

    for (size_t i = 0; i < sizeof(special_ips) / sizeof(special_ips[0]); i++) {
        int16_t old = sauron_set(ctx, special_ips[i], 100);
        int16_t got = sauron_get(ctx, special_ips[i]);
        printf("  %s: set returned %d, get returned %d\n",
               special_ips[i], old, got);
    }

    /* ------------------------------------------------------------ */
    printf("\n\n=== Decay Operation ===\n");
    /* ------------------------------------------------------------ */

    /* Set up some scores for decay test */
    sauron_set(ctx, "45.33.40.1", 100);
    sauron_set(ctx, "45.33.40.2", 50);
    sauron_set(ctx, "45.33.40.3", 10);
    sauron_set(ctx, "45.33.40.4", 5);
    sauron_set(ctx, "45.33.40.5", -100);

    printf("\nBefore decay:\n");
    printf("  45.33.40.1: %d\n", sauron_get(ctx, "45.33.40.1"));
    printf("  45.33.40.2: %d\n", sauron_get(ctx, "45.33.40.2"));
    printf("  45.33.40.3: %d\n", sauron_get(ctx, "45.33.40.3"));
    printf("  45.33.40.4: %d\n", sauron_get(ctx, "45.33.40.4"));
    printf("  45.33.40.5: %d\n", sauron_get(ctx, "45.33.40.5"));

    /* Apply 50% decay with deadzone of 10 */
    uint64_t modified = sauron_decay(ctx, 0.5f, 10);
    printf("\nAfter decay(0.5, deadzone=10) - %lu scores modified:\n",
           (unsigned long)modified);
    printf("  45.33.40.1: %d (was 100 -> 50)\n", sauron_get(ctx, "45.33.40.1"));
    printf("  45.33.40.2: %d (was 50 -> 25)\n", sauron_get(ctx, "45.33.40.2"));
    printf("  45.33.40.3: %d (was 10 -> deleted, in deadzone)\n",
           sauron_get(ctx, "45.33.40.3"));
    printf("  45.33.40.4: %d (was 5 -> deleted, in deadzone)\n",
           sauron_get(ctx, "45.33.40.4"));
    printf("  45.33.40.5: %d (was -100 -> -50)\n", sauron_get(ctx, "45.33.40.5"));

    /* ------------------------------------------------------------ */
    printf("\n\n=== Persistence (Save/Load) ===\n");
    /* ------------------------------------------------------------ */

    const char *archive_file = "/tmp/sauron_example.dat";

    /* Clear and set known values */
    sauron_clear(ctx);
    sauron_set(ctx, "192.168.1.1", 111);
    sauron_set(ctx, "192.168.1.2", 222);
    sauron_set(ctx, "192.168.1.3", 333);

    printf("\nBefore save: count=%lu\n", (unsigned long)sauron_count(ctx));
    printf("  192.168.1.1: %d\n", sauron_get(ctx, "192.168.1.1"));
    printf("  192.168.1.2: %d\n", sauron_get(ctx, "192.168.1.2"));
    printf("  192.168.1.3: %d\n", sauron_get(ctx, "192.168.1.3"));

    /* Save to file */
    int ret = sauron_save(ctx, archive_file);
    if (ret != SAURON_OK) {
        fprintf(stderr, "ERROR: Failed to save archive\n");
    } else {
        printf("\n[OK] Saved to %s\n", archive_file);
    }

    /* Clear and verify empty */
    sauron_clear(ctx);
    printf("\nAfter clear: count=%lu\n", (unsigned long)sauron_count(ctx));
    printf("  192.168.1.1: %d (should be 0)\n", sauron_get(ctx, "192.168.1.1"));

    /* Load from file */
    ret = sauron_load(ctx, archive_file);
    if (ret != SAURON_OK) {
        fprintf(stderr, "ERROR: Failed to load archive\n");
    } else {
        printf("\n[OK] Loaded from %s\n", archive_file);
    }

    printf("\nAfter load: count=%lu\n", (unsigned long)sauron_count(ctx));
    printf("  192.168.1.1: %d (should be 111)\n", sauron_get(ctx, "192.168.1.1"));
    printf("  192.168.1.2: %d (should be 222)\n", sauron_get(ctx, "192.168.1.2"));
    printf("  192.168.1.3: %d (should be 333)\n", sauron_get(ctx, "192.168.1.3"));

    /* Cleanup archive file */
    unlink(archive_file);

    /* ------------------------------------------------------------ */
    printf("\n\n=== Bulk Loading ===\n");
    /* ------------------------------------------------------------ */

    /* Create a test CSV file */
    const char *bulk_file = "/tmp/sauron_bulk_example.csv";
    FILE *fp = fopen(bulk_file, "w");
    if (!fp) {
        fprintf(stderr, "ERROR: Cannot create bulk file\n");
    } else {
        fprintf(fp, "# Example bulk load file\n");
        fprintf(fp, "# Format: IP,SCORE or IP,+DELTA or IP,+-DELTA\n");
        fprintf(fp, "45.33.50.1,100\n");    /* Set to 100 */
        fprintf(fp, "45.33.50.2,-50\n");    /* Set to -50 */
        fprintf(fp, "45.33.50.3,+25\n");    /* Add 25 */
        fprintf(fp, "45.33.50.1,+10\n");    /* Add 10 to existing 100 */
        fprintf(fp, "45.33.50.4,+-5\n");    /* Subtract 5 from current (0) */
        fclose(fp);
        printf("\nCreated test file: %s\n", bulk_file);
    }

    sauron_clear(ctx);
    sauron_bulk_result_t result;
    ret = sauron_bulk_load(ctx, bulk_file, &result);

    if (ret != SAURON_OK) {
        fprintf(stderr, "ERROR: Bulk load failed\n");
    } else {
        printf("\nBulk load results:\n");
        printf("  Lines processed: %lu\n", (unsigned long)result.lines_processed);
        printf("  Sets: %lu\n", (unsigned long)result.sets);
        printf("  Updates: %lu\n", (unsigned long)result.updates);
        printf("  Skipped: %lu\n", (unsigned long)result.lines_skipped);
        printf("  Elapsed: %.6f seconds\n", result.elapsed_seconds);
        printf("  Rate: %.0f lines/sec\n", result.lines_per_second);

        printf("\nVerifying loaded scores:\n");
        printf("  45.33.50.1: %d (expected 110 = 100 + 10)\n",
               sauron_get(ctx, "45.33.50.1"));
        printf("  45.33.50.2: %d (expected -50)\n",
               sauron_get(ctx, "45.33.50.2"));
        printf("  45.33.50.3: %d (expected 25)\n",
               sauron_get(ctx, "45.33.50.3"));
        printf("  45.33.50.4: %d (expected -5)\n",
               sauron_get(ctx, "45.33.50.4"));
    }

    unlink(bulk_file);

    /* ------------------------------------------------------------ */
    printf("\n\n=== Performance Demonstration ===\n");
    /* ------------------------------------------------------------ */

    sauron_clear(ctx);

    printf("\nTiming 1 million set/get operations:\n");

    double start = get_time();
    for (int i = 0; i < 1000000; i++) {
        /* Generate different /24 blocks to stress test */
        uint32_t ip = 0x01000001 + (uint32_t)i;  /* 1.0.0.1 + i */
        if ((ip >> 24) < 127 || (ip >> 24) > 127) {  /* Skip loopback */
            sauron_set_u32(ctx, ip, (int16_t)(i % 32767));
        }
    }
    double set_time = get_time() - start;

    start = get_time();
    int64_t checksum = 0;
    for (int i = 0; i < 1000000; i++) {
        uint32_t ip = 0x01000001 + (uint32_t)i;
        checksum += sauron_get_u32(ctx, ip);
    }
    double get_time_elapsed = get_time() - start;

    printf("  Set: %.3f sec (%.1fM ops/sec)\n",
           set_time, 1.0 / set_time);
    printf("  Get: %.3f sec (%.1fM ops/sec)\n",
           get_time_elapsed, 1.0 / get_time_elapsed);
    printf("  Checksum: %ld (prevents optimization)\n", (long)checksum);

    print_stats(ctx, "Final State");

    /* Cleanup */
    sauron_destroy(ctx);
    printf("\n[OK] Destroyed context - all resources freed\n");

    printf("\n=================================\n");
    printf("Example completed successfully\n");
    printf("=================================\n");

    return 0;
}
