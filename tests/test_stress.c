/****
 *
 * Sauron Stress Test Suite
 * Long-running stability and consistency tests
 *
 * Copyright (c) 2024-2026, Ron Dilley
 *
 ****/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <stdatomic.h>
#include "../include/sauron.h"

#define NUM_THREADS 8
#define OPS_PER_THREAD 500000
#define STRESS_DURATION_SEC 10

static sauron_ctx_t *g_ctx;
static atomic_int g_running;
static atomic_uint_fast64_t g_ops_count;
static atomic_int g_errors;

static double get_time_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/****
 * Test 1: Data Consistency Under Concurrent Access
 *
 * Multiple threads increment the same IP addresses.
 * Verify final counts are correct.
 ****/

typedef struct {
    int thread_id;
    int increments_per_ip;
} consistency_args_t;

static void *consistency_thread(void *arg)
{
    consistency_args_t *a = (consistency_args_t *)arg;

    /* Each thread increments 256 IPs in the same /24 */
    for (int round = 0; round < a->increments_per_ip; round++) {
        for (int host = 0; host < 256; host++) {
            uint32_t ip = 0xC0A80100 | (uint32_t)host;  /* 192.168.1.x */
            sauron_incr_u32(g_ctx, ip, 1);
            atomic_fetch_add(&g_ops_count, 1);
        }
    }

    return NULL;
}

static int test_data_consistency(void)
{
    printf("Test 1: Data Consistency Under Concurrent Access\n");
    printf("-" "-------------------------------------------------\n");

    g_ctx = sauron_create();
    atomic_store(&g_ops_count, 0);
    atomic_store(&g_errors, 0);

    int increments_per_ip = 1000;
    pthread_t threads[NUM_THREADS];
    consistency_args_t args[NUM_THREADS];

    double start = get_time_sec();

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        args[i].increments_per_ip = increments_per_ip;
        pthread_create(&threads[i], NULL, consistency_thread, &args[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    double elapsed = get_time_sec() - start;

    /* Verify all IPs have the expected count */
    int errors = 0;
    int32_t total_expected = NUM_THREADS * increments_per_ip;
    int16_t expected = (total_expected > 32767) ? 32767 : (int16_t)total_expected;

    for (int host = 0; host < 256; host++) {
        uint32_t ip = 0xC0A80100 | (uint32_t)host;
        int16_t actual = sauron_get_u32(g_ctx, ip);
        if (actual != expected) {
            if (errors < 10) {
                printf("  ERROR: IP 192.168.1.%d expected %d, got %d\n",
                       host, expected, actual);
            }
            errors++;
        }
    }

    uint64_t ops = atomic_load(&g_ops_count);
    printf("  Threads: %d, Ops: %lu, Time: %.2fs, Rate: %.0f ops/sec\n",
           NUM_THREADS, (unsigned long)ops, elapsed, ops / elapsed);

    if (errors > 0) {
        printf("  FAIL: %d IPs had incorrect values\n\n", errors);
        sauron_destroy(g_ctx);
        return 1;
    }

    printf("  PASS: All 256 IPs have correct value (%d)\n\n", expected);
    sauron_destroy(g_ctx);
    return 0;
}

/****
 * Test 2: Long-Running Stability
 *
 * Run mixed operations for a fixed duration.
 * Check for crashes, memory growth, or errors.
 ****/

static void *stability_worker(void *arg)
{
    int thread_id = *(int *)arg;
    uint32_t seed = (uint32_t)(thread_id * 12345);

    while (atomic_load(&g_running)) {
        /* Simple PRNG */
        seed = seed * 1103515245 + 12345;
        uint32_t ip = (seed >> 8) & 0x0FFFFFFF;  /* Avoid bogons */
        ip |= 0x0A000000;  /* 10.x.x.x range */

        int op = (seed >> 4) % 10;

        switch (op) {
            case 0:
            case 1:
            case 2:
            case 3:
                /* 40% GET */
                sauron_get_u32(g_ctx, ip);
                break;
            case 4:
            case 5:
                /* 20% SET */
                sauron_set_u32(g_ctx, ip, (int16_t)(seed & 0x7FFF));
                break;
            case 6:
            case 7:
                /* 20% INCR */
                sauron_incr_u32(g_ctx, ip, (int16_t)((seed & 0xFF) - 128));
                break;
            case 8:
                /* 10% DELETE */
                sauron_delete_u32(g_ctx, ip);
                break;
            case 9:
                /* 10% DECR */
                sauron_decr_u32(g_ctx, ip, (int16_t)(seed & 0xFF));
                break;
        }

        atomic_fetch_add(&g_ops_count, 1);
    }

    return NULL;
}

static int test_long_running_stability(void)
{
    printf("Test 2: Long-Running Stability (%d seconds)\n", STRESS_DURATION_SEC);
    printf("-" "-------------------------------------------------\n");

    g_ctx = sauron_create();
    atomic_store(&g_running, 1);
    atomic_store(&g_ops_count, 0);

    size_t initial_mem = sauron_memory_usage(g_ctx);

    pthread_t threads[NUM_THREADS];
    int thread_ids[NUM_THREADS];

    double start = get_time_sec();

    for (int i = 0; i < NUM_THREADS; i++) {
        thread_ids[i] = i;
        pthread_create(&threads[i], NULL, stability_worker, &thread_ids[i]);
    }

    /* Let it run */
    sleep(STRESS_DURATION_SEC);

    /* Stop threads */
    atomic_store(&g_running, 0);

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    double elapsed = get_time_sec() - start;
    uint64_t ops = atomic_load(&g_ops_count);
    size_t final_mem = sauron_memory_usage(g_ctx);
    uint64_t scores = sauron_count(g_ctx);
    uint64_t blocks = sauron_block_count(g_ctx);

    printf("  Duration: %.2f sec\n", elapsed);
    printf("  Total ops: %lu (%.0f ops/sec)\n", (unsigned long)ops, ops / elapsed);
    printf("  Final scores: %lu in %lu blocks\n",
           (unsigned long)scores, (unsigned long)blocks);
    printf("  Memory: %zu -> %zu bytes\n", initial_mem, final_mem);

    /* Check for reasonable memory growth */
    size_t expected_max = initial_mem + (blocks * 600);  /* ~540 bytes/block + overhead */
    if (final_mem > expected_max * 2) {
        printf("  FAIL: Memory usage seems excessive\n\n");
        sauron_destroy(g_ctx);
        return 1;
    }

    printf("  PASS: No crashes, memory growth reasonable\n\n");
    sauron_destroy(g_ctx);
    return 0;
}

/****
 * Test 3: Decay Under Load
 *
 * Run decay while other threads are reading/writing.
 ****/

static void *decay_worker(void *arg)
{
    (void)arg;

    while (atomic_load(&g_running)) {
        /* Continuous decay operations */
        uint64_t modified = sauron_decay(g_ctx, 0.999f, 1);
        (void)modified;
        atomic_fetch_add(&g_ops_count, 1);

        /* Small delay to allow other operations */
        struct timespec ts = {0, 100000};  /* 0.1ms */
        nanosleep(&ts, NULL);
    }

    return NULL;
}

static void *reader_writer(void *arg)
{
    int thread_id = *(int *)arg;
    uint32_t seed = (uint32_t)(thread_id * 54321);

    while (atomic_load(&g_running)) {
        seed = seed * 1103515245 + 12345;
        uint32_t ip = 0xAC100000 | (seed & 0xFFFFFF);  /* 172.16.x.x */

        if (seed & 1) {
            sauron_incr_u32(g_ctx, ip, 10);
        } else {
            sauron_get_u32(g_ctx, ip);
        }

        atomic_fetch_add(&g_ops_count, 1);
    }

    return NULL;
}

static int test_decay_under_load(void)
{
    printf("Test 3: Decay Under Load (%d seconds)\n", STRESS_DURATION_SEC / 2);
    printf("-" "-------------------------------------------------\n");

    g_ctx = sauron_create();
    atomic_store(&g_running, 1);
    atomic_store(&g_ops_count, 0);

    /* Pre-populate with some data */
    for (int i = 0; i < 10000; i++) {
        uint32_t ip = 0xAC100000 | (uint32_t)i;
        sauron_set_u32(g_ctx, ip, 1000);
    }

    pthread_t decay_thread;
    pthread_t worker_threads[NUM_THREADS - 1];
    int thread_ids[NUM_THREADS - 1];

    double start = get_time_sec();

    /* Start decay thread */
    pthread_create(&decay_thread, NULL, decay_worker, NULL);

    /* Start reader/writer threads */
    for (int i = 0; i < NUM_THREADS - 1; i++) {
        thread_ids[i] = i;
        pthread_create(&worker_threads[i], NULL, reader_writer, &thread_ids[i]);
    }

    /* Let it run */
    sleep(STRESS_DURATION_SEC / 2);

    /* Stop threads */
    atomic_store(&g_running, 0);

    pthread_join(decay_thread, NULL);
    for (int i = 0; i < NUM_THREADS - 1; i++) {
        pthread_join(worker_threads[i], NULL);
    }

    double elapsed = get_time_sec() - start;
    uint64_t ops = atomic_load(&g_ops_count);
    uint64_t scores = sauron_count(g_ctx);

    printf("  Duration: %.2f sec\n", elapsed);
    printf("  Total ops: %lu (%.0f ops/sec)\n", (unsigned long)ops, ops / elapsed);
    printf("  Final scores: %lu\n", (unsigned long)scores);
    printf("  PASS: No crashes during concurrent decay\n\n");

    sauron_destroy(g_ctx);
    return 0;
}

/****
 * Test 4: Block Allocation Stress
 *
 * Rapidly allocate many /24 blocks from multiple threads.
 ****/

static void *allocator_thread(void *arg)
{
    int thread_id = *(int *)arg;

    /* Each thread allocates its own range of /24s */
    for (int i = 0; i < 1000; i++) {
        /* Spread across address space to force new block allocation */
        uint32_t ip = ((uint32_t)thread_id << 24) | ((uint32_t)i << 8) | 1;
        if ((ip >> 24) == 127 || (ip >> 24) >= 224) {
            ip = 0x0A000000 | ((uint32_t)thread_id << 16) | ((uint32_t)i << 8) | 1;
        }
        sauron_set_u32(g_ctx, ip, 1);
        atomic_fetch_add(&g_ops_count, 1);
    }

    return NULL;
}

static int test_block_allocation_stress(void)
{
    printf("Test 4: Block Allocation Stress\n");
    printf("-" "-------------------------------------------------\n");

    g_ctx = sauron_create();
    atomic_store(&g_ops_count, 0);

    uint64_t initial_blocks = sauron_block_count(g_ctx);

    pthread_t threads[NUM_THREADS];
    int thread_ids[NUM_THREADS];

    double start = get_time_sec();

    for (int i = 0; i < NUM_THREADS; i++) {
        thread_ids[i] = i;
        pthread_create(&threads[i], NULL, allocator_thread, &thread_ids[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    double elapsed = get_time_sec() - start;
    uint64_t ops = atomic_load(&g_ops_count);
    uint64_t final_blocks = sauron_block_count(g_ctx);
    uint64_t scores = sauron_count(g_ctx);

    printf("  Threads: %d, Ops: %lu, Time: %.3fs\n",
           NUM_THREADS, (unsigned long)ops, elapsed);
    printf("  Blocks: %lu -> %lu (allocated %lu)\n",
           (unsigned long)initial_blocks, (unsigned long)final_blocks,
           (unsigned long)(final_blocks - initial_blocks));
    printf("  Scores: %lu\n", (unsigned long)scores);

    /* Verify we got blocks */
    if (final_blocks < 100) {
        printf("  FAIL: Too few blocks allocated\n\n");
        sauron_destroy(g_ctx);
        return 1;
    }

    printf("  PASS: Block allocation under concurrent stress\n\n");
    sauron_destroy(g_ctx);
    return 0;
}

/****
 * Test 5: Persistence Stress
 *
 * Save/load repeatedly while data is changing.
 ****/

static void *persistence_modifier(void *arg)
{
    int thread_id = *(int *)arg;
    uint32_t seed = (uint32_t)(thread_id * 11111);

    while (atomic_load(&g_running)) {
        seed = seed * 1103515245 + 12345;
        uint32_t ip = 0xC0A80000 | (seed & 0xFFFF);  /* 192.168.x.x */
        sauron_incr_u32(g_ctx, ip, 1);
        atomic_fetch_add(&g_ops_count, 1);
    }

    return NULL;
}

static int test_persistence_stress(void)
{
    printf("Test 5: Persistence Under Load\n");
    printf("-" "-------------------------------------------------\n");

    g_ctx = sauron_create();
    atomic_store(&g_running, 1);
    atomic_store(&g_ops_count, 0);
    atomic_store(&g_errors, 0);

    /* Pre-populate */
    for (int i = 0; i < 1000; i++) {
        sauron_set(g_ctx, "192.168.0.1", 100);
    }

    pthread_t modifier_threads[NUM_THREADS / 2];
    int thread_ids[NUM_THREADS / 2];

    /* Start modifier threads */
    for (int i = 0; i < NUM_THREADS / 2; i++) {
        thread_ids[i] = i;
        pthread_create(&modifier_threads[i], NULL, persistence_modifier, &thread_ids[i]);
    }

    /* Main thread does save/load cycles */
    int save_load_cycles = 20;
    int save_errors = 0;
    int load_errors = 0;

    for (int i = 0; i < save_load_cycles; i++) {
        char filename[64];
        snprintf(filename, sizeof(filename), "/tmp/sauron_stress_%d.dat", i % 3);

        if (sauron_save(g_ctx, filename) != SAURON_OK) {
            save_errors++;
        }

        /* Small delay */
        struct timespec ts = {0, 10000000};  /* 10ms */
        nanosleep(&ts, NULL);

        /* Load into a separate context to verify */
        sauron_ctx_t *verify = sauron_create();
        if (sauron_load(verify, filename) != SAURON_OK) {
            load_errors++;
        }
        sauron_destroy(verify);
    }

    /* Stop modifier threads */
    atomic_store(&g_running, 0);

    for (int i = 0; i < NUM_THREADS / 2; i++) {
        pthread_join(modifier_threads[i], NULL);
    }

    uint64_t ops = atomic_load(&g_ops_count);

    printf("  Modifier threads: %d\n", NUM_THREADS / 2);
    printf("  Total modifications: %lu\n", (unsigned long)ops);
    printf("  Save/load cycles: %d\n", save_load_cycles);
    printf("  Save errors: %d, Load errors: %d\n", save_errors, load_errors);

    /* Cleanup */
    for (int i = 0; i < 3; i++) {
        char filename[64];
        snprintf(filename, sizeof(filename), "/tmp/sauron_stress_%d.dat", i);
        unlink(filename);
    }

    if (save_errors > 0 || load_errors > 0) {
        printf("  FAIL: Persistence errors under load\n\n");
        sauron_destroy(g_ctx);
        return 1;
    }

    printf("  PASS: Save/load reliable under concurrent modifications\n\n");
    sauron_destroy(g_ctx);
    return 0;
}

/****
 * Test 6: Memory Leak Check
 *
 * Create/destroy contexts repeatedly, check for leaks.
 ****/

static int test_memory_leak_check(void)
{
    printf("Test 6: Memory Leak Check (create/destroy cycles)\n");
    printf("-" "-------------------------------------------------\n");

    int cycles = 100;
    int ops_per_cycle = 10000;

    /* Get baseline - create/destroy empty context */
    sauron_ctx_t *ctx = sauron_create();
    size_t empty_ctx_mem = sauron_memory_usage(ctx);
    sauron_destroy(ctx);

    printf("  Cycles: %d, Ops per cycle: %d\n", cycles, ops_per_cycle);
    printf("  Empty context memory: %zu bytes\n", empty_ctx_mem);

    double start = get_time_sec();

    for (int c = 0; c < cycles; c++) {
        ctx = sauron_create();

        /* Add some data */
        for (int i = 0; i < ops_per_cycle; i++) {
            uint32_t ip = 0x0A000000 | (uint32_t)i;
            sauron_set_u32(ctx, ip, (int16_t)(i & 0x7FFF));
        }

        /* Apply decay */
        sauron_decay(ctx, 0.5f, 100);

        /* Save to file */
        sauron_save(ctx, "/tmp/sauron_leak_test.dat");

        /* Destroy - should free all memory */
        sauron_destroy(ctx);
    }

    double elapsed = get_time_sec() - start;

    /* Create one more to check memory */
    ctx = sauron_create();
    size_t final_empty_mem = sauron_memory_usage(ctx);
    sauron_destroy(ctx);

    unlink("/tmp/sauron_leak_test.dat");

    printf("  Time: %.2f sec\n", elapsed);
    printf("  Final empty context memory: %zu bytes\n", final_empty_mem);

    /* Memory should be the same as initial empty context */
    if (final_empty_mem != empty_ctx_mem) {
        printf("  WARNING: Memory size differs (may not indicate leak)\n");
    }

    printf("  PASS: Context create/destroy cycles completed\n");
    printf("  NOTE: Run with valgrind for definitive leak detection\n\n");

    return 0;
}

/****
 * Main
 ****/

int main(void)
{
    int failures = 0;

    printf("Sauron Stress Test Suite v%s\n", sauron_version());
    printf("=================================================\n\n");

    failures += test_data_consistency();
    failures += test_long_running_stability();
    failures += test_decay_under_load();
    failures += test_block_allocation_stress();
    failures += test_persistence_stress();
    failures += test_memory_leak_check();

    printf("=================================================\n");
    if (failures == 0) {
        printf("All stress tests passed!\n");
    } else {
        printf("%d stress test(s) FAILED!\n", failures);
    }

    return failures;
}
