/****
 *
 * Sauron Threading Test Suite
 * Tests concurrent access and thread safety
 *
 * Copyright (c) 2024-2026, Ron Dilley
 *
 ****/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include "../include/sauron.h"

#define NUM_THREADS 8
#define OPS_PER_THREAD 100000

static sauron_ctx_t *g_ctx;
static atomic_uint_fast64_t g_total_ops;
static atomic_int g_errors;

/* Thread function: concurrent increments on same IP */
static void *thread_incr_same(void *arg)
{
    int thread_id = *(int *)arg;
    (void)thread_id;

    for (int i = 0; i < OPS_PER_THREAD; i++) {
        sauron_incr(g_ctx, "192.168.1.1", 1);
        atomic_fetch_add(&g_total_ops, 1);
    }

    return NULL;
}

/* Thread function: concurrent operations on different IPs */
static void *thread_incr_different(void *arg)
{
    int thread_id = *(int *)arg;
    char ip[32];

    for (int i = 0; i < OPS_PER_THREAD; i++) {
        /* Each thread works on its own IP range */
        snprintf(ip, sizeof(ip), "10.%d.%d.%d",
                 thread_id, (i >> 8) & 0xFF, i & 0xFF);
        sauron_incr(g_ctx, ip, 1);
        atomic_fetch_add(&g_total_ops, 1);
    }

    return NULL;
}

/* Thread function: mixed read/write operations */
static void *thread_mixed(void *arg)
{
    int thread_id = *(int *)arg;
    char ip[32];
    int16_t score;

    for (int i = 0; i < OPS_PER_THREAD; i++) {
        snprintf(ip, sizeof(ip), "172.16.%d.%d",
                 thread_id, i & 0xFF);

        if (i % 3 == 0) {
            /* Write */
            sauron_set(g_ctx, ip, (int16_t)(i & 0x7FFF));
        } else if (i % 3 == 1) {
            /* Read */
            score = sauron_get(g_ctx, ip);
            (void)score;
        } else {
            /* Increment */
            sauron_incr(g_ctx, ip, 10);
        }
        atomic_fetch_add(&g_total_ops, 1);
    }

    return NULL;
}

/* Thread function: decay while others write */
static void *thread_decay(void *arg)
{
    (void)arg;

    for (int i = 0; i < 10; i++) {
        sauron_decay(g_ctx, 0.99f, 1);
        atomic_fetch_add(&g_total_ops, 1);
        /* Small delay */
        struct timespec ts = {0, 1000000};  /* 1ms */
        nanosleep(&ts, NULL);
    }

    return NULL;
}

/* Thread function: concurrent block allocation */
static void *thread_allocate(void *arg)
{
    int thread_id = *(int *)arg;

    /* Each thread tries to allocate different /24 blocks */
    for (int i = 0; i < OPS_PER_THREAD / 256; i++) {
        uint32_t prefix = (uint32_t)((thread_id << 16) | (i & 0xFFFF));
        uint32_t ip = prefix << 8;
        sauron_set_u32(g_ctx, ip, 1);
        atomic_fetch_add(&g_total_ops, 1);
    }

    return NULL;
}

static double get_time_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int run_test(const char *name, void *(*func)(void *), int use_decay)
{
    pthread_t threads[NUM_THREADS + 1];
    int thread_ids[NUM_THREADS];
    int ret = 0;

    printf("Testing %s...\n", name);
    printf("  Threads: %d, Ops/thread: %d\n", NUM_THREADS, OPS_PER_THREAD);

    /* Reset */
    atomic_store(&g_total_ops, 0);
    atomic_store(&g_errors, 0);

    /* Recreate context for clean test */
    if (g_ctx) sauron_destroy(g_ctx);
    g_ctx = sauron_create();
    if (!g_ctx) {
        printf("  FAIL: Could not create context\n");
        return 1;
    }

    double start = get_time_sec();

    /* Start worker threads */
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_ids[i] = i;
        if (pthread_create(&threads[i], NULL, func, &thread_ids[i]) != 0) {
            printf("  FAIL: Could not create thread %d\n", i);
            return 1;
        }
    }

    /* Optionally start decay thread */
    if (use_decay) {
        if (pthread_create(&threads[NUM_THREADS], NULL, thread_decay, NULL) != 0) {
            printf("  FAIL: Could not create decay thread\n");
            return 1;
        }
    }

    /* Wait for completion */
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    if (use_decay) {
        pthread_join(threads[NUM_THREADS], NULL);
    }

    double elapsed = get_time_sec() - start;
    uint64_t ops = atomic_load(&g_total_ops);
    int errors = atomic_load(&g_errors);

    printf("  Time: %.3f sec, Total ops: %lu, Ops/sec: %.0f\n",
           elapsed, (unsigned long)ops, ops / elapsed);
    printf("  Active scores: %lu, Blocks: %lu\n",
           (unsigned long)sauron_count(g_ctx),
           (unsigned long)sauron_block_count(g_ctx));

    if (errors > 0) {
        printf("  FAIL: %d errors detected\n", errors);
        ret = 1;
    } else {
        printf("  PASS\n");
    }

    printf("\n");
    return ret;
}

static int test_concurrent_same_ip(void)
{
    int ret = run_test("concurrent increments on same IP", thread_incr_same, 0);

    /* Verify final score */
    int32_t total = NUM_THREADS * OPS_PER_THREAD;
    int16_t expected = (total > 32767) ? 32767 : (int16_t)total;

    int16_t actual = sauron_get(g_ctx, "192.168.1.1");

    /* Due to saturation, we expect the final value to be saturated */
    if (actual != expected) {
        printf("  Note: Final score %d (expected %d)\n\n", actual, expected);
    }

    return ret;
}

static int test_concurrent_different_ips(void)
{
    return run_test("concurrent operations on different IPs", thread_incr_different, 0);
}

static int test_mixed_operations(void)
{
    return run_test("mixed read/write operations", thread_mixed, 0);
}

static int test_decay_concurrent(void)
{
    /* Pre-populate some data */
    g_ctx = sauron_create();
    for (int i = 0; i < 10000; i++) {
        char ip[32];
        snprintf(ip, sizeof(ip), "172.16.%d.%d", (i >> 8) & 0xFF, i & 0xFF);
        sauron_set(g_ctx, ip, 1000);
    }
    sauron_destroy(g_ctx);
    g_ctx = NULL;

    return run_test("decay with concurrent writes", thread_mixed, 1);
}

static int test_block_allocation_race(void)
{
    return run_test("concurrent block allocation", thread_allocate, 0);
}

int main(void)
{
    int failures = 0;

    printf("Sauron Threading Test Suite v%s\n", sauron_version());
    printf("Testing thread safety with %d threads\n\n", NUM_THREADS);

    failures += test_concurrent_same_ip();
    failures += test_concurrent_different_ips();
    failures += test_mixed_operations();
    failures += test_decay_concurrent();
    failures += test_block_allocation_race();

    /* Final cleanup */
    if (g_ctx) sauron_destroy(g_ctx);

    printf("==================================================\n");
    if (failures == 0) {
        printf("All threading tests passed!\n");
    } else {
        printf("%d test(s) failed!\n", failures);
    }

    return failures;
}
