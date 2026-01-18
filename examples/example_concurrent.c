/*
 * Sauron Library - Concurrent Stress Test
 *
 * Exercises thread safety by running simultaneous:
 * - Random IP readers (multiple threads)
 * - Bulk score updaters (multiple threads)
 * - Decay operations (single thread, periodic)
 *
 * Build:
 *   gcc -O2 -pthread -o example_concurrent example_concurrent.c \
 *       -I../include -L../src/.libs -lsauron -Wl,-rpath,../src/.libs
 *
 * Run:
 *   ./example_concurrent [duration_seconds] [num_reader_threads] [num_writer_threads]
 *   ./example_concurrent 10 4 2   # 10 seconds, 4 readers, 2 writers
 *
 * Copyright (c) 2024-2026, Ron Dilley
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
#include <locale.h>
#include <sauron.h>

/* Configuration */
#define DEFAULT_DURATION_SEC 10
#define DEFAULT_READER_THREADS 4
#define DEFAULT_WRITER_THREADS 2
#define DECAY_INTERVAL_MS 500
#define BULK_BATCH_SIZE 10000

/* Global shared state */
static sauron_ctx_t *g_ctx;
static atomic_int g_running;
static atomic_uint_least64_t g_total_reads;
static atomic_uint_least64_t g_total_writes;
static atomic_uint_least64_t g_total_decays;
static atomic_uint_least64_t g_read_errors;
static atomic_uint_least64_t g_write_errors;

/* Simple PRNG for thread-local randomness (xorshift32) */
static uint32_t xorshift32(uint32_t *state)
{
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

/* Generate a random non-bogon IP */
static uint32_t random_valid_ip(uint32_t *rng_state)
{
    uint32_t ip;
    int attempts = 0;

    ip = xorshift32(rng_state);
    /* Ensure we get a valid first octet (1-126, 128-223) */
    uint8_t first = (ip >> 24) & 0xFF;
    if (first == 0 || first == 127 || first >= 224) {
        /* Remap to valid range */
        first = 1 + (first % 126);  /* 1-126 */
        if (first >= 127) first++;   /* Skip 127 */
        ip = (ip & 0x00FFFFFF) | ((uint32_t)first << 24);
    }
    (void)attempts;  /* Unused after bogon check removal */

    return ip;
}

static double get_time(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/*
 * Reader thread: Continuously reads random IPs
 */
static void *reader_thread(void *arg)
{
    (void)arg;
    uint32_t rng_state = (uint32_t)time(NULL) ^ (uint32_t)(uintptr_t)pthread_self();
    uint64_t local_reads = 0;

    while (atomic_load(&g_running)) {
        uint32_t ip = random_valid_ip(&rng_state);
        int16_t score = sauron_get_u32(g_ctx, ip);
        (void)score;  /* Used */

        local_reads++;

        /* Update global counter periodically */
        if ((local_reads & 0x3FFF) == 0) {
            atomic_fetch_add(&g_total_reads, local_reads);
            local_reads = 0;
            sched_yield();
        }
    }

    /* Final update */
    atomic_fetch_add(&g_total_reads, local_reads);
    return NULL;
}

/*
 * Writer thread: Continuously sets/increments random IPs
 */
static void *writer_thread(void *arg)
{
    (void)arg;
    uint32_t rng_state = (uint32_t)time(NULL) ^ (uint32_t)(uintptr_t)pthread_self() ^ 0xDEADBEEF;
    uint64_t local_writes = 0;

    while (atomic_load(&g_running)) {
        uint32_t ip = random_valid_ip(&rng_state);

        /* Mix of set and increment operations */
        int op = xorshift32(&rng_state) % 3;
        int16_t value = (int16_t)((xorshift32(&rng_state) % 1000) - 500);

        switch (op) {
        case 0:
            sauron_set_u32(g_ctx, ip, value);
            break;
        case 1:
            sauron_incr_u32(g_ctx, ip, value);
            break;
        case 2:
            sauron_decr_u32(g_ctx, ip, (int16_t)abs(value));
            break;
        }

        local_writes++;

        /* Update global counter periodically */
        if ((local_writes & 0xFFF) == 0) {
            atomic_fetch_add(&g_total_writes, local_writes);
            local_writes = 0;
            sched_yield();
        }
    }

    atomic_fetch_add(&g_total_writes, local_writes);
    return NULL;
}

/*
 * Bulk loader thread: Periodically bulk loads batches
 */
static void *bulk_loader_thread(void *arg)
{
    (void)arg;
    uint32_t rng_state = (uint32_t)time(NULL) ^ 0xCAFEBABE;
    char *buffer = malloc(BULK_BATCH_SIZE * 32);  /* ~32 bytes per line */

    if (!buffer) {
        fprintf(stderr, "ERROR: Failed to allocate bulk buffer\n");
        return NULL;
    }

    while (atomic_load(&g_running)) {
        /* Generate a batch of random updates */
        char *p = buffer;
        for (int i = 0; i < BULK_BATCH_SIZE; i++) {
            uint32_t ip = random_valid_ip(&rng_state);
            int16_t value = (int16_t)((xorshift32(&rng_state) % 200) - 100);
            int is_relative = xorshift32(&rng_state) % 2;

            int a = (ip >> 24) & 0xFF;
            int b = (ip >> 16) & 0xFF;
            int c = (ip >> 8) & 0xFF;
            int d = ip & 0xFF;

            if (is_relative) {
                p += sprintf(p, "%d.%d.%d.%d,+%d\n", a, b, c, d, value);
            } else {
                p += sprintf(p, "%d.%d.%d.%d,%d\n", a, b, c, d, value);
            }
        }

        sauron_bulk_result_t result;
        int ret = sauron_bulk_load_buffer(g_ctx, buffer, p - buffer, &result);

        if (ret == SAURON_OK) {
            atomic_fetch_add(&g_total_writes, result.sets + result.updates);
        }

        /* Small delay between bulk loads */
        usleep(10000);  /* 10ms */
    }

    free(buffer);
    return NULL;
}

/*
 * Decay thread: Periodically applies decay
 */
static void *decay_thread(void *arg)
{
    (void)arg;

    while (atomic_load(&g_running)) {
        uint64_t modified = sauron_decay(g_ctx, 0.99f, 1);
        atomic_fetch_add(&g_total_decays, modified);

        /* Sleep between decay cycles */
        usleep(DECAY_INTERVAL_MS * 1000);
    }

    return NULL;
}

/*
 * Stats reporter thread: Periodically prints statistics
 */
static void *stats_thread(void *arg)
{
    (void)arg;
    uint64_t last_reads = 0;
    uint64_t last_writes = 0;
    double last_time = get_time();
    int interval = 0;

    while (atomic_load(&g_running)) {
        sleep(1);
        interval++;

        uint64_t reads = atomic_load(&g_total_reads);
        uint64_t writes = atomic_load(&g_total_writes);
        double now = get_time();
        double elapsed = now - last_time;

        uint64_t read_delta = reads - last_reads;
        uint64_t write_delta = writes - last_writes;

        printf("  [%2ds] Reads: %'12lu (%'.1fM/s) | Writes: %'12lu (%'.1fM/s) | "
               "Count: %'lu | Blocks: %lu\n",
               interval,
               (unsigned long)reads, read_delta / elapsed / 1e6,
               (unsigned long)writes, write_delta / elapsed / 1e6,
               (unsigned long)sauron_count(g_ctx),
               (unsigned long)sauron_block_count(g_ctx));

        last_reads = reads;
        last_writes = writes;
        last_time = now;
    }

    return NULL;
}

int main(int argc, char **argv)
{
    int duration_sec = DEFAULT_DURATION_SEC;
    int num_readers = DEFAULT_READER_THREADS;
    int num_writers = DEFAULT_WRITER_THREADS;

    if (argc > 1) duration_sec = atoi(argv[1]);
    if (argc > 2) num_readers = atoi(argv[2]);
    if (argc > 3) num_writers = atoi(argv[3]);

    /* Enable locale for number formatting */
    setlocale(LC_NUMERIC, "");

    printf("Sauron Concurrent Stress Test\n");
    printf("==============================\n");
    printf("Duration: %d seconds\n", duration_sec);
    printf("Reader threads: %d\n", num_readers);
    printf("Writer threads: %d\n", num_writers);
    printf("Bulk loader threads: 1\n");
    printf("Decay thread: 1 (every %dms)\n", DECAY_INTERVAL_MS);
    printf("Library version: %s\n\n", sauron_version());

    /* Create context */
    g_ctx = sauron_create();
    if (!g_ctx) {
        fprintf(stderr, "ERROR: Failed to create context\n");
        return 1;
    }

    /* Pre-populate with some data */
    printf("Pre-populating with 100K entries...\n");
    uint32_t rng = 12345;
    for (int i = 0; i < 100000; i++) {
        uint32_t ip = random_valid_ip(&rng);
        sauron_set_u32(g_ctx, ip, (int16_t)(i % 1000));
    }
    printf("Initial count: %'lu, blocks: %lu\n\n",
           (unsigned long)sauron_count(g_ctx),
           (unsigned long)sauron_block_count(g_ctx));

    /* Initialize global state */
    atomic_store(&g_running, 1);
    atomic_store(&g_total_reads, 0);
    atomic_store(&g_total_writes, 0);
    atomic_store(&g_total_decays, 0);
    atomic_store(&g_read_errors, 0);
    atomic_store(&g_write_errors, 0);

    /* Allocate thread handles */
    int total_threads = num_readers + num_writers + 3;  /* +bulk +decay +stats */
    pthread_t *threads = malloc(total_threads * sizeof(pthread_t));

    printf("Starting concurrent operations...\n\n");
    double start_time = get_time();

    int t = 0;

    /* Start reader threads */
    for (int i = 0; i < num_readers; i++) {
        pthread_create(&threads[t++], NULL, reader_thread, NULL);
    }

    /* Start writer threads */
    for (int i = 0; i < num_writers; i++) {
        pthread_create(&threads[t++], NULL, writer_thread, NULL);
    }

    /* Start bulk loader thread */
    pthread_create(&threads[t++], NULL, bulk_loader_thread, NULL);

    /* Start decay thread */
    pthread_create(&threads[t++], NULL, decay_thread, NULL);

    /* Start stats thread */
    pthread_create(&threads[t++], NULL, stats_thread, NULL);

    /* Run for specified duration */
    sleep(duration_sec);

    /* Signal threads to stop */
    atomic_store(&g_running, 0);

    printf("\nStopping threads...\n");

    /* Wait for all threads */
    for (int i = 0; i < total_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    double elapsed = get_time() - start_time;

    /* Get final results */
    uint64_t total_reads = atomic_load(&g_total_reads);
    uint64_t total_writes = atomic_load(&g_total_writes);
    uint64_t total_decays = atomic_load(&g_total_decays);
    uint64_t read_errors = atomic_load(&g_read_errors);
    uint64_t write_errors = atomic_load(&g_write_errors);

    printf("\n==============================\n");
    printf("RESULTS\n");
    printf("==============================\n");
    printf("Duration: %.2f seconds\n", elapsed);
    printf("Total reads: %'lu (%.2fM/sec)\n",
           (unsigned long)total_reads, total_reads / elapsed / 1e6);
    printf("Total writes: %'lu (%.2fM/sec)\n",
           (unsigned long)total_writes, total_writes / elapsed / 1e6);
    printf("Total decay modifications: %'lu\n", (unsigned long)total_decays);
    printf("Read errors: %lu\n", (unsigned long)read_errors);
    printf("Write errors: %lu\n", (unsigned long)write_errors);
    printf("Final count: %'lu\n", (unsigned long)sauron_count(g_ctx));
    printf("Final blocks: %lu\n", (unsigned long)sauron_block_count(g_ctx));
    printf("Final memory: %.2f MB\n", sauron_memory_usage(g_ctx) / (1024.0 * 1024.0));

    int pass = (read_errors == 0 && write_errors == 0);
    printf("\nRESULT: %s\n", pass ? "PASS - No errors detected" : "FAIL - Errors detected");

    /* Cleanup */
    sauron_destroy(g_ctx);
    free(threads);

    return pass ? 0 : 1;
}
