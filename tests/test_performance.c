/****
 *
 * Sauron Performance Test Suite
 * Comprehensive benchmarks with performance targets
 *
 * Copyright (c) 2024-2026, Ron Dilley
 *
 ****/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include "../include/sauron.h"

#define MIN_OPS_PER_SEC 2000000  /* 2M ops/sec minimum target */

static double get_time_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

typedef struct {
    sauron_ctx_t *ctx;
    uint64_t ops;
    int thread_id;
    int num_threads;
} bench_args_t;

static void *bench_get_thread(void *arg)
{
    bench_args_t *a = (bench_args_t *)arg;
    uint64_t ops = a->ops / a->num_threads;
    volatile int16_t sink = 0;

    for (uint64_t i = 0; i < ops; i++) {
        uint32_t ip = (uint32_t)(((a->thread_id * ops + i) & 0xFFFF) << 16) |
                      (uint32_t)((a->thread_id * ops + i) & 0xFF);
        sink = sauron_get_u32(a->ctx, ip);
    }
    (void)sink;

    return NULL;
}

static void *bench_set_thread(void *arg)
{
    bench_args_t *a = (bench_args_t *)arg;
    uint64_t ops = a->ops / a->num_threads;

    for (uint64_t i = 0; i < ops; i++) {
        uint32_t ip = (uint32_t)(((a->thread_id * ops + i) & 0xFFFF) << 16) |
                      (uint32_t)((a->thread_id * ops + i) & 0xFF);
        sauron_set_u32(a->ctx, ip, (int16_t)(i & 0x7FFF));
    }

    return NULL;
}

static void *bench_incr_thread(void *arg)
{
    bench_args_t *a = (bench_args_t *)arg;
    uint64_t ops = a->ops / a->num_threads;

    for (uint64_t i = 0; i < ops; i++) {
        uint32_t ip = 0xC0A80000 | (uint32_t)(i & 0xFF);
        sauron_incr_u32(a->ctx, ip, 1);
    }

    return NULL;
}

static double run_multi_thread_bench(sauron_ctx_t *ctx, int num_threads,
                                     uint64_t total_ops, void *(*func)(void *))
{
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    bench_args_t *args = malloc(num_threads * sizeof(bench_args_t));

    double start = get_time_sec();

    for (int i = 0; i < num_threads; i++) {
        args[i].ctx = ctx;
        args[i].ops = total_ops;
        args[i].thread_id = i;
        args[i].num_threads = num_threads;
        pthread_create(&threads[i], NULL, func, &args[i]);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    double elapsed = get_time_sec() - start;

    free(threads);
    free(args);

    return total_ops / elapsed;
}

static int test_single_threaded_performance(void)
{
    int failures = 0;
    sauron_ctx_t *ctx = sauron_create();
    uint64_t ops = 2000000;
    double ops_per_sec;

    printf("Single-Threaded Performance (target: >%d ops/sec)\n", MIN_OPS_PER_SEC);
    printf("-" "------------------------------------------------\n");

    /* SET benchmark */
    double start = get_time_sec();
    for (uint64_t i = 0; i < ops; i++) {
        uint32_t ip = (uint32_t)((i & 0xFFFF) << 16) | (uint32_t)(i & 0xFF);
        sauron_set_u32(ctx, ip, (int16_t)(i & 0x7FFF));
    }
    ops_per_sec = ops / (get_time_sec() - start);
    printf("  SET (u32):  %12.0f ops/sec  %s\n",
           ops_per_sec, ops_per_sec >= MIN_OPS_PER_SEC ? "PASS" : "FAIL");
    if (ops_per_sec < MIN_OPS_PER_SEC) failures++;

    /* GET benchmark */
    volatile int16_t sink = 0;
    start = get_time_sec();
    for (uint64_t i = 0; i < ops; i++) {
        uint32_t ip = (uint32_t)((i & 0xFFFF) << 16) | (uint32_t)(i & 0xFF);
        sink = sauron_get_u32(ctx, ip);
    }
    ops_per_sec = ops / (get_time_sec() - start);
    printf("  GET (u32):  %12.0f ops/sec  %s\n",
           ops_per_sec, ops_per_sec >= MIN_OPS_PER_SEC ? "PASS" : "FAIL");
    if (ops_per_sec < MIN_OPS_PER_SEC) failures++;
    (void)sink;

    /* INCR benchmark */
    start = get_time_sec();
    for (uint64_t i = 0; i < ops; i++) {
        uint32_t ip = 0xC0A80000 | (uint32_t)(i & 0xFF);
        sauron_incr_u32(ctx, ip, 1);
    }
    ops_per_sec = ops / (get_time_sec() - start);
    printf("  INCR (u32): %12.0f ops/sec  %s\n",
           ops_per_sec, ops_per_sec >= MIN_OPS_PER_SEC ? "PASS" : "FAIL");
    if (ops_per_sec < MIN_OPS_PER_SEC) failures++;

    /* String IP benchmark (slower due to parsing) */
    start = get_time_sec();
    for (uint64_t i = 0; i < ops / 10; i++) {
        char ip[32];
        snprintf(ip, sizeof(ip), "10.%lu.%lu.%lu",
                 (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF);
        sauron_get(ctx, ip);
    }
    ops_per_sec = (ops / 10) / (get_time_sec() - start);
    printf("  GET (str):  %12.0f ops/sec  (string parsing overhead)\n", ops_per_sec);

    sauron_destroy(ctx);
    printf("\n");

    return failures;
}

static int test_multi_threaded_performance(void)
{
    int failures = 0;
    int thread_counts[] = {2, 4, 8};
    int num_tests = sizeof(thread_counts) / sizeof(thread_counts[0]);
    uint64_t ops = 4000000;
    double ops_per_sec;

    printf("Multi-Threaded Performance\n");
    printf("-" "------------------------------------------------\n");

    for (int t = 0; t < num_tests; t++) {
        int threads = thread_counts[t];
        sauron_ctx_t *ctx = sauron_create();

        /* Pre-populate for GET test */
        for (uint64_t i = 0; i < ops / 4; i++) {
            uint32_t ip = (uint32_t)((i & 0xFFFF) << 16) | (uint32_t)(i & 0xFF);
            sauron_set_u32(ctx, ip, (int16_t)(i & 0x7FFF));
        }

        printf("  %d threads:\n", threads);

        /* GET benchmark */
        ops_per_sec = run_multi_thread_bench(ctx, threads, ops, bench_get_thread);
        printf("    GET:  %12.0f ops/sec  (%.1fx speedup)\n",
               ops_per_sec, ops_per_sec / MIN_OPS_PER_SEC);

        /* SET benchmark - recreate ctx */
        sauron_destroy(ctx);
        ctx = sauron_create();
        ops_per_sec = run_multi_thread_bench(ctx, threads, ops, bench_set_thread);
        printf("    SET:  %12.0f ops/sec  (%.1fx speedup)\n",
               ops_per_sec, ops_per_sec / MIN_OPS_PER_SEC);

        /* INCR benchmark on same block (contention test) */
        ops_per_sec = run_multi_thread_bench(ctx, threads, ops, bench_incr_thread);
        printf("    INCR: %12.0f ops/sec  (same /24, high contention)\n", ops_per_sec);

        sauron_destroy(ctx);
    }

    printf("\n");
    return failures;
}

static int test_memory_efficiency(void)
{
    int failures = 0;
    sauron_ctx_t *ctx = sauron_create();

    printf("Memory Efficiency\n");
    printf("-" "------------------------------------------------\n");

    size_t initial_mem = sauron_memory_usage(ctx);
    printf("  Initial memory:     %10zu bytes\n", initial_mem);

    /* Add 1000 IPs across 100 /24 blocks */
    for (int block = 0; block < 100; block++) {
        for (int host = 0; host < 10; host++) {
            char ip[32];
            snprintf(ip, sizeof(ip), "10.0.%d.%d", block, host);
            sauron_set(ctx, ip, 100);
        }
    }

    uint64_t count = sauron_count(ctx);
    uint64_t blocks = sauron_block_count(ctx);
    size_t mem = sauron_memory_usage(ctx);

    printf("  After 1000 IPs:     %10zu bytes (%lu blocks)\n", mem, (unsigned long)blocks);
    printf("  Bytes per score:    %10.1f\n", (double)(mem - initial_mem) / count);
    printf("  Bytes per block:    %10.1f\n", (double)(mem - initial_mem) / blocks);

    /* Expected: ~528 bytes per block (256 scores * 2 + overhead) */
    double bytes_per_block = (double)(mem - initial_mem) / blocks;
    if (bytes_per_block > 1000) {
        printf("  FAIL: Memory per block too high (expected ~528 bytes)\n");
        failures++;
    } else {
        printf("  PASS: Memory efficiency within expected range\n");
    }

    sauron_destroy(ctx);
    printf("\n");

    return failures;
}

static int test_decay_performance(void)
{
    int failures = 0;
    sauron_ctx_t *ctx = sauron_create();

    printf("Decay Performance\n");
    printf("-" "------------------------------------------------\n");

    /* Populate with 100K scores across 1000 blocks */
    for (int i = 0; i < 100000; i++) {
        char ip[32];
        snprintf(ip, sizeof(ip), "10.%d.%d.%d",
                 (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF);
        sauron_set(ctx, ip, 1000);
    }

    uint64_t count_before = sauron_count(ctx);
    uint64_t blocks_before = sauron_block_count(ctx);
    printf("  Scores before decay: %lu (%lu blocks)\n",
           (unsigned long)count_before, (unsigned long)blocks_before);

    double start = get_time_sec();
    uint64_t modified = sauron_decay(ctx, 0.9f, 10);
    double elapsed = get_time_sec() - start;

    printf("  Decay time:          %.3f sec\n", elapsed);
    printf("  Scores modified:     %lu\n", (unsigned long)modified);
    printf("  Decay rate:          %.0f scores/sec\n", modified / elapsed);

    /* Verify decay was applied */
    int16_t score = sauron_get(ctx, "10.0.0.1");
    if (score != 900) {
        printf("  FAIL: Expected score 900 after 0.9 decay, got %d\n", score);
        failures++;
    } else {
        printf("  PASS: Decay correctly applied (1000 -> 900)\n");
    }

    sauron_destroy(ctx);
    printf("\n");

    return failures;
}

static int test_persistence_performance(void)
{
    int failures = 0;
    sauron_ctx_t *ctx = sauron_create();
    const char *filename = "/tmp/sauron_perf_test.dat";

    printf("Persistence Performance\n");
    printf("-" "------------------------------------------------\n");

    /* Populate with 50K scores */
    for (int i = 0; i < 50000; i++) {
        char ip[32];
        snprintf(ip, sizeof(ip), "10.%d.%d.%d",
                 (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF);
        sauron_set(ctx, ip, (int16_t)(i & 0x7FFF));
    }

    uint64_t count = sauron_count(ctx);

    /* Save benchmark */
    double start = get_time_sec();
    int ret = sauron_save(ctx, filename);
    double save_time = get_time_sec() - start;

    if (ret != SAURON_OK) {
        printf("  FAIL: Save failed\n");
        failures++;
    } else {
        printf("  Save time:  %.3f sec (%lu scores, %.0f scores/sec)\n",
               save_time, (unsigned long)count, count / save_time);
    }

    /* Load benchmark */
    sauron_ctx_t *ctx2 = sauron_create();
    start = get_time_sec();
    ret = sauron_load(ctx2, filename);
    double load_time = get_time_sec() - start;

    if (ret != SAURON_OK) {
        printf("  FAIL: Load failed\n");
        failures++;
    } else {
        printf("  Load time:  %.3f sec (%lu scores, %.0f scores/sec)\n",
               load_time, (unsigned long)sauron_count(ctx2),
               sauron_count(ctx2) / load_time);
    }

    /* Verify data integrity */
    int16_t score = sauron_get(ctx2, "10.0.0.100");
    int16_t expected = 100 & 0x7FFF;
    if (score != expected) {
        printf("  FAIL: Data integrity error (expected %d, got %d)\n", expected, score);
        failures++;
    } else {
        printf("  PASS: Data integrity verified\n");
    }

    /* Cleanup */
    unlink(filename);
    sauron_destroy(ctx);
    sauron_destroy(ctx2);
    printf("\n");

    return failures;
}

int main(void)
{
    int failures = 0;

    printf("Sauron Performance Test Suite v%s\n", sauron_version());
    printf("=================================================\n\n");

    failures += test_single_threaded_performance();
    failures += test_multi_threaded_performance();
    failures += test_memory_efficiency();
    failures += test_decay_performance();
    failures += test_persistence_performance();

    printf("=================================================\n");
    if (failures == 0) {
        printf("All performance tests passed!\n");
    } else {
        printf("%d performance test(s) failed!\n", failures);
    }

    return failures;
}
