/*
 * Focused SET benchmark for profiling
 */

#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "../include/sauron.h"

#define NUM_OPS 10000000

static double get_time_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(void)
{
    sauron_ctx_t *ctx = sauron_create();
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        return 1;
    }

    printf("Running %d SET operations...\n", NUM_OPS);

    double start = get_time_sec();

    for (uint64_t i = 0; i < NUM_OPS; i++) {
        /* Spread across many /24 blocks */
        uint32_t ip = (uint32_t)((i & 0xFFFF) << 16) | (uint32_t)(i & 0xFF);
        sauron_set_u32(ctx, ip, (int16_t)(i & 0x7FFF));
    }

    double elapsed = get_time_sec() - start;
    double ops_per_sec = NUM_OPS / elapsed;

    printf("Completed in %.3f sec\n", elapsed);
    printf("SET rate: %.2f M ops/sec\n", ops_per_sec / 1e6);
    printf("Scores: %lu, Blocks: %lu\n",
           (unsigned long)sauron_count(ctx),
           (unsigned long)sauron_block_count(ctx));

    sauron_destroy(ctx);
    return 0;
}
