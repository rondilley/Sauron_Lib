/*
 * Sauron Library - Comprehensive Stress Test
 *
 * Tests library under heavy concurrent load with detailed metrics:
 * - Bulk loading at scale (1M, 10M, 100M entries)
 * - Concurrent random reads with hit/miss tracking
 * - Periodic decay operations
 * - CPU, memory, and I/O monitoring
 *
 * Build:
 *   gcc -O2 -pthread -o stress_test stress_test.c \
 *       -I../include -L../src/.libs -lsauron -Wl,-rpath,../src/.libs
 *
 * Run:
 *   ./stress_test [preset]
 *   ./stress_test small    # 1M entries, 10s
 *   ./stress_test medium   # 10M entries, 30s
 *   ./stress_test large    # 100M entries, 60s
 *   ./stress_test custom <entries> <duration> <readers> <writers>
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
#include <sys/resource.h>
#include <sauron.h>

/* Test presets */
typedef struct {
    const char *name;
    uint64_t initial_entries;
    int duration_sec;
    int reader_threads;
    int writer_threads;
    int bulk_batch_size;
    int decay_interval_ms;
} test_preset_t;

static const test_preset_t PRESETS[] = {
    {"small",  1000000,   10, 4, 2, 10000,  500},
    {"medium", 10000000,  30, 8, 4, 50000,  1000},
    {"large",  100000000, 60, 8, 4, 100000, 2000},
};

/* Global shared state */
static sauron_ctx_t *g_ctx;
static atomic_int g_running;
static atomic_int g_loading_complete;

/* Read metrics */
static atomic_uint_least64_t g_read_ops;
static atomic_uint_least64_t g_read_hits;
static atomic_uint_least64_t g_read_misses;

/* Write metrics */
static atomic_uint_least64_t g_write_ops;
static atomic_uint_least64_t g_bulk_lines;
static atomic_uint_least64_t g_bulk_batches;

/* Decay metrics */
static atomic_uint_least64_t g_decay_ops;
static atomic_uint_least64_t g_decay_modified;

/* Error counters */
static atomic_uint_least64_t g_errors;

/* System metrics */
typedef struct {
    double user_cpu_sec;
    double sys_cpu_sec;
    long max_rss_kb;
    uint64_t read_bytes;
    uint64_t write_bytes;
} sys_metrics_t;

/* Test configuration */
static test_preset_t g_config;

/* IP pool for targeted reads (IPs we know exist) */
#define IP_POOL_SIZE 1000000
static uint32_t *g_ip_pool;
static atomic_uint_least64_t g_ip_pool_count;

/* Simple PRNG (xorshift32) */
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
    uint8_t first = (ip >> 24) & 0xFF;
    /* Avoid problematic ranges for cleaner testing */
    if (first == 0 || first == 127 || first >= 224) {
        first = 1 + (first % 126);
        if (first >= 127) first++;
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

/* Get system metrics */
static void get_sys_metrics(sys_metrics_t *m)
{
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);

    m->user_cpu_sec = usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1e6;
    m->sys_cpu_sec = usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1e6;
    m->max_rss_kb = usage.ru_maxrss;

    /* Read I/O stats from /proc */
    m->read_bytes = 0;
    m->write_bytes = 0;
    FILE *fp = fopen("/proc/self/io", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "read_bytes:", 11) == 0) {
                m->read_bytes = strtoull(line + 12, NULL, 10);
            } else if (strncmp(line, "write_bytes:", 12) == 0) {
                m->write_bytes = strtoull(line + 13, NULL, 10);
            }
        }
        fclose(fp);
    }
}

/*
 * Reader thread: Maximum speed reads with hit/miss tracking
 */
static void *reader_thread(void *arg)
{
    int thread_id = (int)(intptr_t)arg;
    uint32_t rng_state = (uint32_t)time(NULL) ^ (uint32_t)thread_id ^ 0x12345678;

    uint64_t local_ops = 0;
    uint64_t local_hits = 0;
    uint64_t local_misses = 0;

    /* Wait for initial load to complete */
    while (!atomic_load(&g_loading_complete) && atomic_load(&g_running)) {
        usleep(1000);
    }

    while (atomic_load(&g_running)) {
        /* Mix of targeted (known IPs) and random reads */
        uint32_t ip;
        int is_targeted = (xorshift32(&rng_state) % 100) < 70;  /* 70% targeted */

        if (is_targeted) {
            uint64_t pool_count = atomic_load(&g_ip_pool_count);
            if (pool_count > 0) {
                uint64_t idx = xorshift32(&rng_state) % pool_count;
                if (idx < IP_POOL_SIZE) {
                    ip = g_ip_pool[idx];
                } else {
                    ip = random_valid_ip(&rng_state);
                }
            } else {
                ip = random_valid_ip(&rng_state);
            }
        } else {
            ip = random_valid_ip(&rng_state);
        }

        int16_t score = sauron_get_u32(g_ctx, ip);

        if (score != 0) {
            local_hits++;
        } else {
            local_misses++;
        }
        local_ops++;

        /* Batch update to reduce atomic contention */
        if ((local_ops & 0x7FFF) == 0) {
            atomic_fetch_add(&g_read_ops, local_ops);
            atomic_fetch_add(&g_read_hits, local_hits);
            atomic_fetch_add(&g_read_misses, local_misses);
            local_ops = 0;
            local_hits = 0;
            local_misses = 0;
        }
    }

    /* Final update */
    atomic_fetch_add(&g_read_ops, local_ops);
    atomic_fetch_add(&g_read_hits, local_hits);
    atomic_fetch_add(&g_read_misses, local_misses);

    return NULL;
}

/*
 * Writer thread: Continuous set/incr/decr operations
 */
static void *writer_thread(void *arg)
{
    int thread_id = (int)(intptr_t)arg;
    uint32_t rng_state = (uint32_t)time(NULL) ^ (uint32_t)thread_id ^ 0xDEADBEEF;

    uint64_t local_ops = 0;

    while (atomic_load(&g_running)) {
        uint32_t ip = random_valid_ip(&rng_state);
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

        /* Track IP in pool for targeted reads */
        if (value != 0) {
            uint64_t idx = atomic_fetch_add(&g_ip_pool_count, 1);
            if (idx < IP_POOL_SIZE) {
                g_ip_pool[idx % IP_POOL_SIZE] = ip;
            }
        }

        local_ops++;

        if ((local_ops & 0xFFF) == 0) {
            atomic_fetch_add(&g_write_ops, local_ops);
            local_ops = 0;
            sched_yield();
        }
    }

    atomic_fetch_add(&g_write_ops, local_ops);
    return NULL;
}

/*
 * Bulk loader thread: Loads large batches periodically
 */
static void *bulk_loader_thread(void *arg)
{
    (void)arg;
    uint32_t rng_state = (uint32_t)time(NULL) ^ 0xCAFEBABE;
    int batch_size = g_config.bulk_batch_size;
    char *buffer = malloc(batch_size * 32);

    if (!buffer) {
        fprintf(stderr, "ERROR: Failed to allocate bulk buffer\n");
        return NULL;
    }

    while (atomic_load(&g_running)) {
        char *p = buffer;
        for (int i = 0; i < batch_size; i++) {
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

                /* Track for targeted reads */
                if (value != 0) {
                    uint64_t idx = atomic_fetch_add(&g_ip_pool_count, 1);
                    if (idx < IP_POOL_SIZE) {
                        g_ip_pool[idx % IP_POOL_SIZE] = ip;
                    }
                }
            }
        }

        sauron_bulk_result_t result;
        int ret = sauron_bulk_load_buffer(g_ctx, buffer, p - buffer, &result);

        if (ret == SAURON_OK) {
            atomic_fetch_add(&g_bulk_lines, result.lines_processed);
            atomic_fetch_add(&g_bulk_batches, 1);
        }

        usleep(50000);  /* 50ms between batches */
    }

    free(buffer);
    return NULL;
}

/*
 * Decay thread: Periodic decay operations
 */
static void *decay_thread(void *arg)
{
    (void)arg;

    while (atomic_load(&g_running)) {
        uint64_t modified = sauron_decay(g_ctx, 0.99f, 5);
        atomic_fetch_add(&g_decay_ops, 1);
        atomic_fetch_add(&g_decay_modified, modified);

        usleep(g_config.decay_interval_ms * 1000);
    }

    return NULL;
}

/*
 * Stats thread: Periodic progress reporting
 */
static void *stats_thread(void *arg)
{
    (void)arg;
    uint64_t last_reads = 0;
    uint64_t last_writes = 0;
    uint64_t last_bulk = 0;
    double last_time = get_time();
    int interval = 0;

    while (atomic_load(&g_running)) {
        sleep(1);
        interval++;

        uint64_t reads = atomic_load(&g_read_ops);
        uint64_t hits = atomic_load(&g_read_hits);
        uint64_t writes = atomic_load(&g_write_ops);
        uint64_t bulk = atomic_load(&g_bulk_lines);
        uint64_t count = sauron_count(g_ctx);

        double now = get_time();
        double dt = now - last_time;

        double read_rate = (reads - last_reads) / dt / 1e6;
        double write_rate = (writes - last_writes) / dt / 1e6;
        double bulk_rate = (bulk - last_bulk) / dt / 1e6;
        double hit_rate = (reads > 0) ? (100.0 * hits / reads) : 0;

        printf("  [%3ds] R: %'.0fM/s (%.1f%% hit) | W: %'.0fM/s | B: %'.0fM/s | "
               "Count: %'lu | Mem: %.0fMB\n",
               interval, read_rate, hit_rate, write_rate, bulk_rate,
               (unsigned long)count,
               sauron_memory_usage(g_ctx) / (1024.0 * 1024.0));

        last_reads = reads;
        last_writes = writes;
        last_bulk = bulk;
        last_time = now;
    }

    return NULL;
}

/*
 * Initial bulk load
 */
static void initial_load(uint64_t count)
{
    printf("Loading %'lu initial entries...\n", (unsigned long)count);

    double start = get_time();
    uint32_t rng = 54321;

    /* Use bulk loading for efficiency */
    int batch_size = 100000;
    char *buffer = malloc(batch_size * 32);
    if (!buffer) {
        fprintf(stderr, "ERROR: Failed to allocate load buffer\n");
        return;
    }

    uint64_t loaded = 0;
    while (loaded < count) {
        int this_batch = (count - loaded > (uint64_t)batch_size) ? batch_size : (int)(count - loaded);
        char *p = buffer;

        for (int i = 0; i < this_batch; i++) {
            uint32_t ip = random_valid_ip(&rng);
            int16_t value = (int16_t)((rng % 2000) - 1000);
            if (value == 0) value = 1;  /* Ensure non-zero */

            int a = (ip >> 24) & 0xFF;
            int b = (ip >> 16) & 0xFF;
            int c = (ip >> 8) & 0xFF;
            int d = ip & 0xFF;

            p += sprintf(p, "%d.%d.%d.%d,%d\n", a, b, c, d, value);

            /* Track for targeted reads */
            uint64_t idx = atomic_fetch_add(&g_ip_pool_count, 1);
            if (idx < IP_POOL_SIZE) {
                g_ip_pool[idx] = ip;
            }

            rng = xorshift32(&rng);
        }

        sauron_bulk_result_t result;
        sauron_bulk_load_buffer(g_ctx, buffer, p - buffer, &result);
        loaded += result.sets + result.updates;

        /* Progress every 10% */
        if ((loaded * 10 / count) > ((loaded - this_batch) * 10 / count)) {
            printf("  ... %'lu / %'lu (%.0f%%)\n",
                   (unsigned long)loaded, (unsigned long)count,
                   100.0 * loaded / count);
        }
    }

    free(buffer);
    double elapsed = get_time() - start;

    printf("Initial load complete: %'lu entries in %.2f sec (%.2fM/sec)\n",
           (unsigned long)sauron_count(g_ctx), elapsed,
           sauron_count(g_ctx) / elapsed / 1e6);
    printf("Memory usage: %.2f MB\n\n", sauron_memory_usage(g_ctx) / (1024.0 * 1024.0));
}

/*
 * Print final metrics in structured format
 */
static void print_metrics(double elapsed, sys_metrics_t *start_metrics, sys_metrics_t *end_metrics)
{
    uint64_t reads = atomic_load(&g_read_ops);
    uint64_t hits = atomic_load(&g_read_hits);
    uint64_t misses = atomic_load(&g_read_misses);
    uint64_t writes = atomic_load(&g_write_ops);
    uint64_t bulk_lines = atomic_load(&g_bulk_lines);
    uint64_t bulk_batches = atomic_load(&g_bulk_batches);
    uint64_t decay_ops = atomic_load(&g_decay_ops);
    uint64_t decay_modified = atomic_load(&g_decay_modified);
    uint64_t errors = atomic_load(&g_errors);

    double cpu_user = end_metrics->user_cpu_sec - start_metrics->user_cpu_sec;
    double cpu_sys = end_metrics->sys_cpu_sec - start_metrics->sys_cpu_sec;
    uint64_t io_read = end_metrics->read_bytes - start_metrics->read_bytes;
    uint64_t io_write = end_metrics->write_bytes - start_metrics->write_bytes;

    printf("\n");
    printf("================================================================================\n");
    printf("STRESS TEST RESULTS: %s\n", g_config.name);
    printf("================================================================================\n");
    printf("\n");
    printf("Configuration:\n");
    printf("  Initial entries:    %'lu\n", (unsigned long)g_config.initial_entries);
    printf("  Duration:           %d seconds\n", g_config.duration_sec);
    printf("  Reader threads:     %d\n", g_config.reader_threads);
    printf("  Writer threads:     %d\n", g_config.writer_threads);
    printf("  Bulk batch size:    %d\n", g_config.bulk_batch_size);
    printf("  Decay interval:     %d ms\n", g_config.decay_interval_ms);
    printf("\n");
    printf("Read Performance:\n");
    printf("  Total reads:        %'lu\n", (unsigned long)reads);
    printf("  Read rate:          %.2f M/sec\n", reads / elapsed / 1e6);
    printf("  Hits:               %'lu (%.2f%%)\n", (unsigned long)hits,
           reads > 0 ? 100.0 * hits / reads : 0);
    printf("  Misses:             %'lu (%.2f%%)\n", (unsigned long)misses,
           reads > 0 ? 100.0 * misses / reads : 0);
    printf("\n");
    printf("Write Performance:\n");
    printf("  Direct writes:      %'lu (%.2f M/sec)\n",
           (unsigned long)writes, writes / elapsed / 1e6);
    printf("  Bulk lines:         %'lu (%.2f M/sec)\n",
           (unsigned long)bulk_lines, bulk_lines / elapsed / 1e6);
    printf("  Bulk batches:       %'lu\n", (unsigned long)bulk_batches);
    printf("  Total writes:       %'lu (%.2f M/sec)\n",
           (unsigned long)(writes + bulk_lines), (writes + bulk_lines) / elapsed / 1e6);
    printf("\n");
    printf("Decay Operations:\n");
    printf("  Decay cycles:       %'lu\n", (unsigned long)decay_ops);
    printf("  Scores modified:    %'lu\n", (unsigned long)decay_modified);
    printf("\n");
    printf("Final State:\n");
    printf("  Active scores:      %'lu\n", (unsigned long)sauron_count(g_ctx));
    printf("  Allocated blocks:   %'lu\n", (unsigned long)sauron_block_count(g_ctx));
    printf("  Library memory:     %.2f MB\n", sauron_memory_usage(g_ctx) / (1024.0 * 1024.0));
    printf("\n");
    printf("System Resources:\n");
    printf("  Wall time:          %.2f sec\n", elapsed);
    printf("  User CPU:           %.2f sec (%.1f%%)\n", cpu_user, 100 * cpu_user / elapsed);
    printf("  System CPU:         %.2f sec (%.1f%%)\n", cpu_sys, 100 * cpu_sys / elapsed);
    printf("  Total CPU:          %.2f sec (%.1f%%)\n", cpu_user + cpu_sys,
           100 * (cpu_user + cpu_sys) / elapsed);
    printf("  Peak RSS:           %'ld KB (%.2f MB)\n",
           end_metrics->max_rss_kb, end_metrics->max_rss_kb / 1024.0);
    printf("  I/O Read:           %'lu bytes (%.2f MB)\n",
           (unsigned long)io_read, io_read / (1024.0 * 1024.0));
    printf("  I/O Write:          %'lu bytes (%.2f MB)\n",
           (unsigned long)io_write, io_write / (1024.0 * 1024.0));
    printf("\n");
    printf("Errors:               %lu\n", (unsigned long)errors);
    printf("\n");
    printf("RESULT: %s\n", errors == 0 ? "PASS" : "FAIL");
    printf("================================================================================\n");

    /* CSV-friendly single line for benchmarking */
    printf("\n[CSV] %s,%lu,%.2f,%lu,%.2f,%.2f,%lu,%.2f,%lu,%.2f,%.2f,%.2f,%.2f,%ld,%lu\n",
           g_config.name,
           (unsigned long)g_config.initial_entries,
           elapsed,
           (unsigned long)reads,
           reads / elapsed / 1e6,
           reads > 0 ? 100.0 * hits / reads : 0,
           (unsigned long)(writes + bulk_lines),
           (writes + bulk_lines) / elapsed / 1e6,
           (unsigned long)sauron_count(g_ctx),
           sauron_memory_usage(g_ctx) / (1024.0 * 1024.0),
           cpu_user + cpu_sys,
           100 * (cpu_user + cpu_sys) / elapsed,
           end_metrics->max_rss_kb / 1024.0,
           end_metrics->max_rss_kb,
           (unsigned long)errors);
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [preset | custom <entries> <duration> <readers> <writers>]\n", prog);
    printf("\n");
    printf("Presets:\n");
    printf("  small   - %'lu entries, %ds (quick validation)\n",
           (unsigned long)PRESETS[0].initial_entries, PRESETS[0].duration_sec);
    printf("  medium  - %'lu entries, %ds (standard test)\n",
           (unsigned long)PRESETS[1].initial_entries, PRESETS[1].duration_sec);
    printf("  large   - %'lu entries, %ds (full stress test)\n",
           (unsigned long)PRESETS[2].initial_entries, PRESETS[2].duration_sec);
    printf("\n");
    printf("Custom:\n");
    printf("  %s custom <entries> <duration_sec> <reader_threads> <writer_threads>\n", prog);
    printf("  Example: %s custom 50000000 45 8 4\n", prog);
}

int main(int argc, char **argv)
{
    setlocale(LC_NUMERIC, "");

    /* Parse arguments */
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "custom") == 0) {
        if (argc < 6) {
            print_usage(argv[0]);
            return 1;
        }
        g_config.name = "custom";
        g_config.initial_entries = strtoull(argv[2], NULL, 10);
        g_config.duration_sec = atoi(argv[3]);
        g_config.reader_threads = atoi(argv[4]);
        g_config.writer_threads = atoi(argv[5]);
        g_config.bulk_batch_size = 50000;
        g_config.decay_interval_ms = 1000;
    } else {
        int found = 0;
        for (size_t i = 0; i < sizeof(PRESETS) / sizeof(PRESETS[0]); i++) {
            if (strcmp(argv[1], PRESETS[i].name) == 0) {
                g_config = PRESETS[i];
                found = 1;
                break;
            }
        }
        if (!found) {
            fprintf(stderr, "ERROR: Unknown preset '%s'\n", argv[1]);
            print_usage(argv[0]);
            return 1;
        }
    }

    printf("================================================================================\n");
    printf("Sauron Stress Test: %s\n", g_config.name);
    printf("================================================================================\n");
    printf("Library version: %s\n", sauron_version());
    printf("\n");

    /* Allocate IP pool */
    g_ip_pool = calloc(IP_POOL_SIZE, sizeof(uint32_t));
    if (!g_ip_pool) {
        fprintf(stderr, "ERROR: Failed to allocate IP pool\n");
        return 1;
    }

    /* Create context */
    g_ctx = sauron_create();
    if (!g_ctx) {
        fprintf(stderr, "ERROR: Failed to create context\n");
        return 1;
    }

    /* Get baseline metrics */
    sys_metrics_t start_metrics, end_metrics;
    get_sys_metrics(&start_metrics);

    /* Initial load */
    initial_load(g_config.initial_entries);
    atomic_store(&g_loading_complete, 1);

    /* Initialize counters */
    atomic_store(&g_running, 1);
    atomic_store(&g_read_ops, 0);
    atomic_store(&g_read_hits, 0);
    atomic_store(&g_read_misses, 0);
    atomic_store(&g_write_ops, 0);
    atomic_store(&g_bulk_lines, 0);
    atomic_store(&g_bulk_batches, 0);
    atomic_store(&g_decay_ops, 0);
    atomic_store(&g_decay_modified, 0);
    atomic_store(&g_errors, 0);

    /* Allocate threads */
    int total_threads = g_config.reader_threads + g_config.writer_threads + 3;
    pthread_t *threads = malloc(total_threads * sizeof(pthread_t));

    printf("Starting stress test: %d readers, %d writers, 1 bulk loader, 1 decay\n",
           g_config.reader_threads, g_config.writer_threads);
    printf("Duration: %d seconds\n\n", g_config.duration_sec);

    double start_time = get_time();
    int t = 0;

    /* Start reader threads */
    for (int i = 0; i < g_config.reader_threads; i++) {
        pthread_create(&threads[t++], NULL, reader_thread, (void *)(intptr_t)i);
    }

    /* Start writer threads */
    for (int i = 0; i < g_config.writer_threads; i++) {
        pthread_create(&threads[t++], NULL, writer_thread, (void *)(intptr_t)(100 + i));
    }

    /* Start bulk loader */
    pthread_create(&threads[t++], NULL, bulk_loader_thread, NULL);

    /* Start decay thread */
    pthread_create(&threads[t++], NULL, decay_thread, NULL);

    /* Start stats thread */
    pthread_create(&threads[t++], NULL, stats_thread, NULL);

    /* Run for duration */
    sleep(g_config.duration_sec);

    /* Stop threads */
    atomic_store(&g_running, 0);
    printf("\nStopping threads...\n");

    for (int i = 0; i < total_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    double elapsed = get_time() - start_time;
    get_sys_metrics(&end_metrics);

    /* Print results */
    print_metrics(elapsed, &start_metrics, &end_metrics);

    /* Cleanup */
    sauron_destroy(g_ctx);
    free(threads);
    free(g_ip_pool);

    return atomic_load(&g_errors) == 0 ? 0 : 1;
}
