/****
 *
 * Sauron - High-Speed IPv4 Scoring Engine
 * Core Implementation
 *
 * Copyright (c) 2024-2026, Ron Dilley
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 ****/

/* Includes */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../include/sysdep.h"
#include "../include/common.h"
#include "../include/sauron.h"
#include "mem.h"
#include "util.h"

/* SIMD support for vectorized decay */
#ifdef HAVE_AVX2
#include <immintrin.h>
#endif

/* Defines */

/* Bitmap size: 2^24 /24 networks = 16M bits = 2MB */
#define BITMAP_SIZE     (1 << 24)
#define BITMAP_BYTES    (BITMAP_SIZE / 8)

/* Number of /16 prefixes (64K) */
#define PREFIX16_COUNT  (1 << 16)

/* Number of /24 blocks per /16 (256) */
#define BLOCKS_PER_16   256

/* Scores per /24 block (256 hosts) */
#define SCORES_PER_BLOCK 256

/* Cache line alignment for performance */
#define CACHE_LINE_SIZE 64

/* Spinlock stripe count for allocation locks */
#define ALLOC_LOCK_STRIPES 256

/* Lock abstraction for VM portability
 * Use --enable-adaptive-mutex to switch from spinlocks to adaptive mutexes.
 * Adaptive mutexes are better for virtualized environments where the hypervisor
 * may preempt a thread holding a spinlock.
 */
#ifdef USE_ADAPTIVE_MUTEX
    typedef pthread_mutex_t sauron_lock_t;

    static inline int sauron_lock_init(sauron_lock_t *lock) {
        pthread_mutexattr_t attr;
        int ret;
        pthread_mutexattr_init(&attr);
        #ifdef PTHREAD_MUTEX_ADAPTIVE_NP
            pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ADAPTIVE_NP);
        #endif
        ret = pthread_mutex_init(lock, &attr);
        pthread_mutexattr_destroy(&attr);
        return ret;
    }

    #define SAURON_LOCK_INIT(lock) sauron_lock_init(lock)
    #define SAURON_LOCK_DESTROY(lock) pthread_mutex_destroy(lock)
    #define SAURON_LOCK(lock) pthread_mutex_lock(lock)
    #define SAURON_UNLOCK(lock) pthread_mutex_unlock(lock)
#else
    typedef pthread_spinlock_t sauron_lock_t;

    #define SAURON_LOCK_INIT(lock) pthread_spin_init(lock, PTHREAD_PROCESS_PRIVATE)
    #define SAURON_LOCK_DESTROY(lock) pthread_spin_destroy(lock)
    #define SAURON_LOCK(lock) pthread_spin_lock(lock)
    #define SAURON_UNLOCK(lock) pthread_spin_unlock(lock)
#endif

/* Global variables */

int quit = FALSE;

/* Library-internal config for utility functions */
PRIVATE Config_t lib_config = {
    .mode = MODE_INTERACTIVE,
    .debug = FALSE,
    .cur_pid = 0
};
Config_t *config = &lib_config;

/* Structs */

/**
 * CIDR /24 block - holds scores for 256 IP addresses.
 * Each block is cache-aligned for performance.
 */
typedef struct cidr_block {
    sauron_lock_t lock;              /* Per-block lock for writes */
    _Atomic(int16_t) scores[SCORES_PER_BLOCK];  /* Atomic scores for each host */
    _Atomic(uint32_t) active_count;  /* Number of non-zero scores in block */
} cidr_block_t;

/**
 * Main scoring engine context.
 * Contains bitmap filter, block pointers, and statistics.
 */
struct sauron_ctx {
    int initialized;

    /* Bitmap filter: 2MB, one bit per /24.
     * Fast negative lookup - if bit is 0, no scores in that /24.
     * Uses atomic operations for thread safety.
     */
    _Atomic(uint8_t) *bitmap;

    /* Two-level block lookup:
     * blocks[/16 prefix] -> array of 256 cidr_block_t pointers (one per /24)
     * NULL means no /24 blocks allocated for that /16.
     */
    _Atomic(cidr_block_t *) *block_ptrs[PREFIX16_COUNT];

    /* Allocation locks: striped by /16 prefix to reduce contention */
    sauron_lock_t alloc_locks[ALLOC_LOCK_STRIPES];

    /* Statistics (atomic for thread-safe reads) */
    _Atomic(uint64_t) score_count;    /* Total non-zero scores */
    _Atomic(uint64_t) block_count;    /* Total allocated /24 blocks */
    _Atomic(size_t) memory_used;      /* Total memory allocated */
};

/* Internal helper functions */

static inline uint32_t ip_to_prefix24(uint32_t ip)
{
    return ip >> 8;
}

static inline uint16_t ip_to_prefix16(uint32_t ip)
{
    return (uint16_t)(ip >> 16);
}

static inline uint8_t ip_to_block_idx(uint32_t ip)
{
    return (uint8_t)((ip >> 8) & 0xFF);
}

static inline uint8_t ip_to_host_idx(uint32_t ip)
{
    return (uint8_t)(ip & 0xFF);
}

static inline void prefix24_to_bitmap_pos(uint32_t prefix24, size_t *byte_idx, uint8_t *bit_idx)
{
    *byte_idx = prefix24 / 8;
    *bit_idx = prefix24 % 8;
}

static inline int bitmap_test(sauron_ctx_t *ctx, uint32_t prefix24)
{
    size_t byte_idx;
    uint8_t bit_idx;
    prefix24_to_bitmap_pos(prefix24, &byte_idx, &bit_idx);
    uint8_t byte_val = atomic_load_explicit(&ctx->bitmap[byte_idx], memory_order_acquire);
    return (byte_val >> bit_idx) & 1;
}

static inline void bitmap_set(sauron_ctx_t *ctx, uint32_t prefix24)
{
    size_t byte_idx;
    uint8_t bit_idx;
    prefix24_to_bitmap_pos(prefix24, &byte_idx, &bit_idx);
    atomic_fetch_or_explicit(&ctx->bitmap[byte_idx], (uint8_t)(1 << bit_idx), memory_order_release);
}

static inline void bitmap_clear(sauron_ctx_t *ctx, uint32_t prefix24)
{
    size_t byte_idx;
    uint8_t bit_idx;
    prefix24_to_bitmap_pos(prefix24, &byte_idx, &bit_idx);
    atomic_fetch_and_explicit(&ctx->bitmap[byte_idx], (uint8_t)~(1 << bit_idx), memory_order_release);
}

static inline pthread_spinlock_t *get_alloc_lock(sauron_ctx_t *ctx, uint16_t prefix16)
{
    return &ctx->alloc_locks[prefix16 % ALLOC_LOCK_STRIPES];
}

static cidr_block_t *alloc_cidr_block(sauron_ctx_t *ctx)
{
    cidr_block_t *block;

    /* Allocate aligned memory for cache performance */
#ifdef HAVE_ALIGNED_ALLOC
    block = (cidr_block_t *)aligned_alloc(CACHE_LINE_SIZE, sizeof(cidr_block_t));
#else
    if (posix_memalign((void **)&block, CACHE_LINE_SIZE, sizeof(cidr_block_t)) != 0)
        block = NULL;
#endif

    if (block == NULL)
        return NULL;

    /* Initialize block */
    memset(block, 0, sizeof(cidr_block_t));
    SAURON_LOCK_INIT(&block->lock);

    /* Update statistics */
    atomic_fetch_add_explicit(&ctx->block_count, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&ctx->memory_used, sizeof(cidr_block_t), memory_order_relaxed);

    return block;
}

static void free_cidr_block(sauron_ctx_t *ctx, cidr_block_t *block)
{
    if (block == NULL)
        return;

    SAURON_LOCK_DESTROY(&block->lock);
    free(block);

    atomic_fetch_sub_explicit(&ctx->block_count, 1, memory_order_relaxed);
    atomic_fetch_sub_explicit(&ctx->memory_used, sizeof(cidr_block_t), memory_order_relaxed);
}

static _Atomic(cidr_block_t *) *alloc_block_ptr_array(sauron_ctx_t *ctx)
{
    _Atomic(cidr_block_t *) *arr;
    size_t arr_size = BLOCKS_PER_16 * sizeof(_Atomic(cidr_block_t *));

#ifdef HAVE_ALIGNED_ALLOC
    arr = (_Atomic(cidr_block_t *) *)aligned_alloc(CACHE_LINE_SIZE, arr_size);
#else
    if (posix_memalign((void **)&arr, CACHE_LINE_SIZE, arr_size) != 0)
        arr = NULL;
#endif

    if (arr == NULL)
        return NULL;

    memset(arr, 0, arr_size);
    atomic_fetch_add_explicit(&ctx->memory_used, arr_size, memory_order_relaxed);

    return arr;
}

static cidr_block_t *get_or_alloc_block(sauron_ctx_t *ctx, uint32_t ip)
{
    uint16_t prefix16 = ip_to_prefix16(ip);
    uint8_t block_idx = ip_to_block_idx(ip);
    uint32_t prefix24 = ip_to_prefix24(ip);
    _Atomic(cidr_block_t *) *block_arr;
    cidr_block_t *block;
    pthread_spinlock_t *lock;

    /* Fast path: check if block pointer array exists */
    block_arr = ctx->block_ptrs[prefix16];
    if (block_arr != NULL) {
        block = atomic_load_explicit(&block_arr[block_idx], memory_order_acquire);
        if (block != NULL) {
            /* Ensure bitmap is set (may have been cleared by decay/clear).
             * Check before setting to avoid expensive atomic write when already set. */
            if (!bitmap_test(ctx, prefix24)) {
                bitmap_set(ctx, prefix24);
            }
            return block;
        }
    }

    /* Slow path: need to allocate, take lock */
    lock = get_alloc_lock(ctx, prefix16);
    SAURON_LOCK(lock);

    /* Double-check after acquiring lock */
    block_arr = ctx->block_ptrs[prefix16];
    if (block_arr == NULL) {
        block_arr = alloc_block_ptr_array(ctx);
        if (block_arr == NULL) {
            SAURON_UNLOCK(lock);
            return NULL;
        }
        atomic_store_explicit((_Atomic(void *) *)&ctx->block_ptrs[prefix16], block_arr, memory_order_release);
    }

    block = atomic_load_explicit(&block_arr[block_idx], memory_order_acquire);
    if (block == NULL) {
        block = alloc_cidr_block(ctx);
        if (block == NULL) {
            SAURON_UNLOCK(lock);
            return NULL;
        }
        atomic_store_explicit(&block_arr[block_idx], block, memory_order_release);
        bitmap_set(ctx, prefix24);
    }

    SAURON_UNLOCK(lock);
    return block;
}

static cidr_block_t *get_block(sauron_ctx_t *ctx, uint32_t ip)
{
    uint16_t prefix16 = ip_to_prefix16(ip);
    uint8_t block_idx = ip_to_block_idx(ip);
    uint32_t prefix24 = ip_to_prefix24(ip);
    _Atomic(cidr_block_t *) *block_arr;

    /* Fast path: check bitmap first */
    if (!bitmap_test(ctx, prefix24))
        return NULL;

    block_arr = ctx->block_ptrs[prefix16];
    if (block_arr == NULL)
        return NULL;

    return atomic_load_explicit(&block_arr[block_idx], memory_order_acquire);
}

/* Lifecycle Functions */

sauron_ctx_t *sauron_create(void)
{
    sauron_ctx_t *ctx;
    int i;

    /* Allocate context structure */
    ctx = (sauron_ctx_t *)XMALLOC(sizeof(sauron_ctx_t));

    /* Allocate bitmap (2MB) */
#ifdef HAVE_ALIGNED_ALLOC
    ctx->bitmap = (_Atomic(uint8_t) *)aligned_alloc(CACHE_LINE_SIZE, BITMAP_BYTES);
#else
    if (posix_memalign((void **)&ctx->bitmap, CACHE_LINE_SIZE, BITMAP_BYTES) != 0)
        ctx->bitmap = NULL;
#endif

    if (ctx->bitmap == NULL) {
        XFREE(ctx);
        return NULL;
    }
    memset((void *)ctx->bitmap, 0, BITMAP_BYTES);

    /* Request transparent hugepages for bitmap (2MB = 1 hugepage)
     * This reduces TLB misses when accessing the bitmap filter.
     * Requires kernel support; silently ignored if unavailable.
     */
#if defined(HAVE_MADVISE) && defined(MADV_HUGEPAGE)
    madvise((void *)ctx->bitmap, BITMAP_BYTES, MADV_HUGEPAGE);
#endif

    /* Initialize block pointer array to NULL */
    for (i = 0; i < PREFIX16_COUNT; i++) {
        ctx->block_ptrs[i] = NULL;
    }

    /* Initialize allocation locks */
    for (i = 0; i < ALLOC_LOCK_STRIPES; i++) {
        SAURON_LOCK_INIT(&ctx->alloc_locks[i]);
    }

    /* Initialize statistics */
    atomic_store(&ctx->score_count, 0);
    atomic_store(&ctx->block_count, 0);
    atomic_store(&ctx->memory_used, sizeof(sauron_ctx_t) + BITMAP_BYTES);

    ctx->initialized = TRUE;

    return ctx;
}

void sauron_destroy(sauron_ctx_t *ctx)
{
    int i, j;
    _Atomic(cidr_block_t *) *block_arr;
    cidr_block_t *block;

    if (ctx == NULL)
        return;

    /* Free all CIDR blocks */
    for (i = 0; i < PREFIX16_COUNT; i++) {
        block_arr = ctx->block_ptrs[i];
        if (block_arr != NULL) {
            for (j = 0; j < BLOCKS_PER_16; j++) {
                block = atomic_load(&block_arr[j]);
                if (block != NULL) {
                    free_cidr_block(ctx, block);
                }
            }
            atomic_fetch_sub_explicit(&ctx->memory_used,
                                      BLOCKS_PER_16 * sizeof(_Atomic(cidr_block_t *)),
                                      memory_order_relaxed);
            free(block_arr);
        }
    }

    /* Destroy allocation locks */
    for (i = 0; i < ALLOC_LOCK_STRIPES; i++) {
        SAURON_LOCK_DESTROY(&ctx->alloc_locks[i]);
    }

    /* Free bitmap */
    if (ctx->bitmap != NULL) {
        free((void *)ctx->bitmap);
    }

    XFREE(ctx);
}

/* Score Operations (uint32_t IP) */

int16_t sauron_get_u32(sauron_ctx_t *ctx, uint32_t ip)
{
    cidr_block_t *block;
    uint8_t host_idx;

    if (ctx == NULL)
        return 0;

    /* Fast path: bitmap check then atomic load */
    block = get_block(ctx, ip);
    if (block == NULL)
        return 0;

    host_idx = ip_to_host_idx(ip);
    return atomic_load_explicit(&block->scores[host_idx], memory_order_acquire);
}

int16_t sauron_set_u32(sauron_ctx_t *ctx, uint32_t ip, int16_t score)
{
    cidr_block_t *block;
    uint8_t host_idx;
    int16_t old_score;

    if (ctx == NULL)
        return 0;

    /* Get or allocate block */
    block = get_or_alloc_block(ctx, ip);
    if (block == NULL)
        return 0;  /* OOM - return 0 as "no change" */

    host_idx = ip_to_host_idx(ip);

    /* Take block lock for write */
    SAURON_LOCK(&block->lock);

    old_score = atomic_load_explicit(&block->scores[host_idx], memory_order_relaxed);
    atomic_store_explicit(&block->scores[host_idx], score, memory_order_release);

    /* Update active count */
    if (old_score == 0 && score != 0) {
        atomic_fetch_add_explicit(&block->active_count, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&ctx->score_count, 1, memory_order_relaxed);
    } else if (old_score != 0 && score == 0) {
        atomic_fetch_sub_explicit(&block->active_count, 1, memory_order_relaxed);
        atomic_fetch_sub_explicit(&ctx->score_count, 1, memory_order_relaxed);
    }

    SAURON_UNLOCK(&block->lock);

    return old_score;
}

static inline int16_t saturating_add(int16_t a, int16_t b)
{
    int32_t result = (int32_t)a + (int32_t)b;
    if (result > SAURON_SCORE_MAX)
        return SAURON_SCORE_MAX;
    if (result < SAURON_SCORE_MIN)
        return SAURON_SCORE_MIN;
    return (int16_t)result;
}

int16_t sauron_incr_u32(sauron_ctx_t *ctx, uint32_t ip, int16_t delta)
{
    cidr_block_t *block;
    uint8_t host_idx;
    int16_t old_score, new_score;

    if (ctx == NULL)
        return 0;

    /* Delta of 0 is a no-op, just return current score */
    if (delta == 0)
        return sauron_get_u32(ctx, ip);

    /* Get or allocate block */
    block = get_or_alloc_block(ctx, ip);
    if (block == NULL)
        return 0;  /* OOM - return 0 as "no change" */

    host_idx = ip_to_host_idx(ip);

    /* Take block lock for write */
    SAURON_LOCK(&block->lock);

    old_score = atomic_load_explicit(&block->scores[host_idx], memory_order_relaxed);
    new_score = saturating_add(old_score, delta);
    atomic_store_explicit(&block->scores[host_idx], new_score, memory_order_release);

    /* Update active count */
    if (old_score == 0 && new_score != 0) {
        atomic_fetch_add_explicit(&block->active_count, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&ctx->score_count, 1, memory_order_relaxed);
    } else if (old_score != 0 && new_score == 0) {
        atomic_fetch_sub_explicit(&block->active_count, 1, memory_order_relaxed);
        atomic_fetch_sub_explicit(&ctx->score_count, 1, memory_order_relaxed);
    }

    SAURON_UNLOCK(&block->lock);

    return new_score;
}

int16_t sauron_decr_u32(sauron_ctx_t *ctx, uint32_t ip, int16_t delta)
{
    /* Handle INT16_MIN edge case to avoid undefined behavior from negation */
    if (delta == INT16_MIN)
        return sauron_incr_u32(ctx, ip, INT16_MAX);  /* Saturate to max decrement */
    return sauron_incr_u32(ctx, ip, (int16_t)(-delta));
}

int sauron_delete_u32(sauron_ctx_t *ctx, uint32_t ip)
{
    cidr_block_t *block;
    uint8_t host_idx;
    int16_t old_score;

    if (ctx == NULL)
        return SAURON_ERR_NULL;

    /* Get block (don't allocate for delete) */
    block = get_block(ctx, ip);
    if (block == NULL)
        return SAURON_OK;  /* Already doesn't exist */

    host_idx = ip_to_host_idx(ip);

    /* Take block lock for write */
    SAURON_LOCK(&block->lock);

    old_score = atomic_load_explicit(&block->scores[host_idx], memory_order_relaxed);
    if (old_score != 0) {
        atomic_store_explicit(&block->scores[host_idx], 0, memory_order_release);
        atomic_fetch_sub_explicit(&block->active_count, 1, memory_order_relaxed);
        atomic_fetch_sub_explicit(&ctx->score_count, 1, memory_order_relaxed);
    }

    SAURON_UNLOCK(&block->lock);

    return SAURON_OK;
}

/* Score Operations (String IP) */

int16_t sauron_get(sauron_ctx_t *ctx, const char *ip)
{
    uint32_t ip_u32;

    if (ctx == NULL || ip == NULL)
        return 0;

    ip_u32 = sauron_ip_to_u32(ip);
    if (ip_u32 == 0)
        return 0;

    return sauron_get_u32(ctx, ip_u32);
}

int16_t sauron_set(sauron_ctx_t *ctx, const char *ip, int16_t score)
{
    uint32_t ip_u32;

    if (ctx == NULL || ip == NULL)
        return 0;

    ip_u32 = sauron_ip_to_u32(ip);
    if (ip_u32 == 0)
        return 0;

    return sauron_set_u32(ctx, ip_u32, score);
}

int16_t sauron_incr(sauron_ctx_t *ctx, const char *ip, int16_t delta)
{
    uint32_t ip_u32;

    if (ctx == NULL || ip == NULL)
        return 0;

    ip_u32 = sauron_ip_to_u32(ip);
    if (ip_u32 == 0)
        return 0;

    return sauron_incr_u32(ctx, ip_u32, delta);
}

int16_t sauron_decr(sauron_ctx_t *ctx, const char *ip, int16_t delta)
{
    /* Handle INT16_MIN edge case to avoid undefined behavior from negation */
    if (delta == INT16_MIN)
        return sauron_incr(ctx, ip, INT16_MAX);  /* Saturate to max decrement */
    return sauron_incr(ctx, ip, (int16_t)(-delta));
}

int sauron_delete(sauron_ctx_t *ctx, const char *ip)
{
    uint32_t ip_u32;

    if (ctx == NULL || ip == NULL)
        return SAURON_ERR_NULL;

    ip_u32 = sauron_ip_to_u32(ip);
    if (ip_u32 == 0)
        return SAURON_ERR_INVALID;

    return sauron_delete_u32(ctx, ip_u32);
}

/* Batch Operations */

int sauron_incr_batch(sauron_ctx_t *ctx, const uint32_t *ips,
                      const int16_t *deltas, size_t count)
{
    size_t i;
    int success_count = 0;

    if (ctx == NULL || ips == NULL || deltas == NULL)
        return 0;

    for (i = 0; i < count; i++) {
        sauron_incr_u32(ctx, ips[i], deltas[i]);
        success_count++;
    }

    return success_count;
}

/* Bulk File Loading */

/* Read buffer size for bulk loading */
#define BULK_READ_BUFFER_SIZE 65536
#define BULK_LINE_MAX 64

static int parse_bulk_line(const char *line, uint32_t *ip_out,
                           int16_t *value_out, int *is_relative_out)
{
    const char *p = line;
    uint32_t ip = 0;
    uint32_t octet = 0;
    int dots = 0;
    int digits = 0;
    int32_t value;
    int is_relative = 0;
    int negative = 0;

    /* Skip leading whitespace */
    while (*p == ' ' || *p == '\t')
        p++;

    /* Parse IP address */
    while (*p != '\0' && *p != ',') {
        if (*p >= '0' && *p <= '9') {
            octet = octet * 10 + (*p - '0');
            digits++;
            if (octet > 255)
                return 0;
        } else if (*p == '.') {
            if (digits == 0)
                return 0;  /* Empty octet */
            if (dots >= 3)
                return 0;
            ip = (ip << 8) | octet;
            octet = 0;
            digits = 0;
            dots++;
        } else if (*p == ' ' || *p == '\t') {
            /* Allow whitespace before comma */
            break;
        } else {
            return 0;  /* Invalid character */
        }
        p++;
    }

    /* Validate IP */
    if (dots != 3 || digits == 0)
        return 0;
    ip = (ip << 8) | octet;

    /* Skip whitespace and find comma */
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p != ',')
        return 0;
    p++;

    /* Skip whitespace after comma */
    while (*p == ' ' || *p == '\t')
        p++;

    /* Check for + prefix (relative update) or - prefix (negative value OR relative)
     * Format: "+N" = relative positive, "-N" = could be negative SET or relative decrement
     * We use "+" prefix ONLY for relative updates, bare "-N" is a SET to negative value.
     * To do relative decrement, user should add to a positive delta: "+N" where N is negative
     * is not valid, so we support "+-N" as relative decrement for clarity.
     *
     * Simplified: Only "+" prefix means relative. "-N" is SET to -N.
     * For relative decrements, use the separate incr API or "+-50" format (future).
     */
    if (*p == '+') {
        is_relative = 1;
        p++;
        /* Check for "+-N" format for relative negative */
        if (*p == '-') {
            negative = 1;
            p++;
        }
    } else if (*p == '-') {
        /* Bare minus = negative absolute value, NOT relative */
        negative = 1;
        p++;
    }

    /* Parse value */
    if (*p < '0' || *p > '9')
        return 0;  /* No digits */

    value = 0;
    while (*p >= '0' && *p <= '9') {
        value = value * 10 + (*p - '0');
        if (value > 32767)
            value = 32767;  /* Saturate */
        p++;
    }

    if (negative)
        value = -value;

    /* Skip trailing whitespace */
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;

    /* Should be at end of meaningful content */
    if (*p != '\0' && *p != '#')  /* Allow comments */
        return 0;

    *ip_out = ip;
    *value_out = (int16_t)value;
    *is_relative_out = is_relative;
    return 1;
}

static double get_time_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

int sauron_bulk_load(sauron_ctx_t *ctx, const char *filename,
                     sauron_bulk_result_t *result)
{
    FILE *fp;
    char *line_buffer;
    size_t line_buffer_size = BULK_LINE_MAX;
    ssize_t line_len;
    uint32_t ip;
    int16_t value;
    int is_relative;
    double start_time, end_time;
    sauron_bulk_result_t stats = {0};

    if (ctx == NULL || filename == NULL)
        return SAURON_ERR_NULL;

    fp = fopen(filename, "r");
    if (fp == NULL)
        return SAURON_ERR_IO;

    /* Allocate line buffer */
    line_buffer = (char *)malloc(line_buffer_size);
    if (line_buffer == NULL) {
        fclose(fp);
        return SAURON_ERR_NOMEM;
    }

    /* Set larger read buffer for performance */
    setvbuf(fp, NULL, _IOFBF, BULK_READ_BUFFER_SIZE);

    start_time = get_time_seconds();

    /* Process lines */
    while ((line_len = getline(&line_buffer, &line_buffer_size, fp)) != -1) {
        stats.lines_processed++;

        /* Skip empty lines and comments */
        if (line_len == 0 || line_buffer[0] == '#' || line_buffer[0] == '\n')
            continue;

        /* Parse line */
        if (!parse_bulk_line(line_buffer, &ip, &value, &is_relative)) {
            stats.parse_errors++;
            stats.lines_skipped++;
            continue;
        }

        /* Apply change */
        if (is_relative) {
            sauron_incr_u32(ctx, ip, value);
            stats.updates++;
        } else {
            sauron_set_u32(ctx, ip, value);
            stats.sets++;
        }
    }

    end_time = get_time_seconds();

    free(line_buffer);
    fclose(fp);

    /* Calculate timing */
    stats.elapsed_seconds = end_time - start_time;
    if (stats.elapsed_seconds > 0.0)
        stats.lines_per_second = (double)stats.lines_processed / stats.elapsed_seconds;
    else
        stats.lines_per_second = 0.0;

    if (result != NULL)
        *result = stats;

    return SAURON_OK;
}

int sauron_bulk_load_buffer(sauron_ctx_t *ctx, const char *data, size_t len,
                            sauron_bulk_result_t *result)
{
    const char *p, *end, *line_start;
    char line_buffer[BULK_LINE_MAX];
    size_t line_len;
    uint32_t ip;
    int16_t value;
    int is_relative;
    double start_time, end_time;
    sauron_bulk_result_t stats = {0};

    if (ctx == NULL || data == NULL)
        return SAURON_ERR_NULL;

    start_time = get_time_seconds();

    p = data;
    end = data + len;

    while (p < end) {
        /* Find line start and end */
        line_start = p;
        while (p < end && *p != '\n')
            p++;

        line_len = (size_t)(p - line_start);
        if (line_len >= BULK_LINE_MAX)
            line_len = BULK_LINE_MAX - 1;

        /* Copy line to buffer and null-terminate */
        memcpy(line_buffer, line_start, line_len);
        line_buffer[line_len] = '\0';

        /* Skip past newline */
        if (p < end && *p == '\n')
            p++;

        stats.lines_processed++;

        /* Skip empty lines and comments */
        if (line_len == 0 || line_buffer[0] == '#')
            continue;

        /* Parse line */
        if (!parse_bulk_line(line_buffer, &ip, &value, &is_relative)) {
            stats.parse_errors++;
            stats.lines_skipped++;
            continue;
        }

        /* Apply change */
        if (is_relative) {
            sauron_incr_u32(ctx, ip, value);
            stats.updates++;
        } else {
            sauron_set_u32(ctx, ip, value);
            stats.sets++;
        }
    }

    end_time = get_time_seconds();

    /* Calculate timing */
    stats.elapsed_seconds = end_time - start_time;
    if (stats.elapsed_seconds > 0.0)
        stats.lines_per_second = (double)stats.lines_processed / stats.elapsed_seconds;
    else
        stats.lines_per_second = 0.0;

    if (result != NULL)
        *result = stats;

    return SAURON_OK;
}

/* Decay */

#ifdef HAVE_AVX2
/**
 * SIMD-optimized decay for a single block (scalar fallback).
 * The SIMD version has precision issues with Q15 fixed-point math,
 * so we use scalar processing which matches the expected behavior exactly.
 *
 * Note: A true SIMD implementation would use _mm256_cvtepi16_ps and
 * _mm256_cvttps_epi32 for float conversion, but that requires unpacking
 * to 32-bit which reduces the SIMD benefit. For now, we use the scalar
 * path which is well-optimized by the compiler.
 *
 * @param block       Block to decay (lock must be held)
 * @param decay_factor Decay factor (0.0-1.0)
 * @param abs_deadzone Absolute deadzone value
 * @param modified    Output: count of modified scores
 * @param zeroed      Output: count of scores that became zero
 */
static void decay_block_simd(cidr_block_t *block, float decay_factor,
                             int16_t abs_deadzone, uint64_t *modified, uint64_t *zeroed)
{
    int i;
    int16_t *scores = (int16_t *)block->scores;  /* Cast away _Atomic under lock */
    int16_t old_score, new_score;

    *modified = 0;
    *zeroed = 0;

    /* Process all scores in the block */
    for (i = 0; i < SCORES_PER_BLOCK; i++) {
        old_score = scores[i];
        if (old_score == 0)
            continue;

        /* Apply decay factor */
        new_score = (int16_t)((float)old_score * decay_factor);

        /* Apply deadzone - delete scores close to 0 */
        if (new_score >= 0 && new_score <= abs_deadzone) {
            new_score = 0;
        } else if (new_score < 0 && new_score >= -abs_deadzone) {
            new_score = 0;
        }

        /* Only count if changed */
        if (new_score != old_score) {
            scores[i] = new_score;
            (*modified)++;

            if (new_score == 0) {
                (*zeroed)++;
            }
        }
    }
}
#endif /* HAVE_AVX2 */

uint64_t sauron_decay(sauron_ctx_t *ctx, float decay_factor, int16_t deadzone)
{
    uint64_t modified = 0;
    int prefix16, block_idx;
    _Atomic(cidr_block_t *) *block_arr;
    cidr_block_t *block;
    int16_t abs_deadzone;
    uint32_t prefix24;
#ifdef HAVE_AVX2
    uint64_t block_modified, block_zeroed;
#else
    int host_idx;
    int16_t old_score, new_score;
#endif

    if (ctx == NULL)
        return 0;

    if (decay_factor < 0.0f || decay_factor > 1.0f)
        return 0;

    /* Ensure deadzone is positive */
    abs_deadzone = (deadzone < 0) ? (int16_t)(-deadzone) : deadzone;

    /* Iterate through all /16 prefixes */
    for (prefix16 = 0; prefix16 < PREFIX16_COUNT; prefix16++) {
        block_arr = ctx->block_ptrs[prefix16];
        if (block_arr == NULL)
            continue;

        /* Iterate through all /24 blocks in this /16 */
        for (block_idx = 0; block_idx < BLOCKS_PER_16; block_idx++) {
            prefix24 = ((uint32_t)prefix16 << 8) | (uint32_t)block_idx;
            if (!bitmap_test(ctx, prefix24))
                continue;

            block = atomic_load_explicit(&block_arr[block_idx], memory_order_acquire);
            if (block == NULL)
                continue;

            /* Skip blocks with no active scores */
            if (atomic_load_explicit(&block->active_count, memory_order_relaxed) == 0) {
                bitmap_clear(ctx, prefix24);
                continue;
            }

            /* Take block lock for modification */
            SAURON_LOCK(&block->lock);

#ifdef HAVE_AVX2
            /* Optimized path with block-level processing */
            decay_block_simd(block, decay_factor, abs_deadzone, &block_modified, &block_zeroed);
            modified += block_modified;

            /* Update global counters */
            if (block_zeroed > 0) {
                atomic_fetch_sub_explicit(&block->active_count, (uint32_t)block_zeroed, memory_order_relaxed);
                atomic_fetch_sub_explicit(&ctx->score_count, block_zeroed, memory_order_relaxed);
            }
#else
            /* Scalar path: iterate through all hosts in this /24 */
            for (host_idx = 0; host_idx < SCORES_PER_BLOCK; host_idx++) {
                old_score = atomic_load_explicit(&block->scores[host_idx], memory_order_relaxed);
                if (old_score == 0)
                    continue;

                /* Apply decay factor */
                new_score = (int16_t)((float)old_score * decay_factor);

                /* Apply deadzone - delete scores close to 0 */
                if (new_score >= 0 && new_score <= abs_deadzone) {
                    new_score = 0;
                } else if (new_score < 0 && new_score >= -abs_deadzone) {
                    new_score = 0;
                }

                /* Only update if changed */
                if (new_score != old_score) {
                    atomic_store_explicit(&block->scores[host_idx], new_score, memory_order_release);
                    modified++;

                    /* Update active count if score became 0 */
                    if (new_score == 0) {
                        atomic_fetch_sub_explicit(&block->active_count, 1, memory_order_relaxed);
                        atomic_fetch_sub_explicit(&ctx->score_count, 1, memory_order_relaxed);
                    }
                }
            }
#endif

            if (atomic_load_explicit(&block->active_count, memory_order_relaxed) == 0) {
                bitmap_clear(ctx, prefix24);
            }

            SAURON_UNLOCK(&block->lock);
        }
    }

    return modified;
}

/* Statistics */

uint64_t sauron_count(sauron_ctx_t *ctx)
{
    if (ctx == NULL)
        return 0;
    return atomic_load_explicit(&ctx->score_count, memory_order_relaxed);
}

uint64_t sauron_block_count(sauron_ctx_t *ctx)
{
    if (ctx == NULL)
        return 0;
    return atomic_load_explicit(&ctx->block_count, memory_order_relaxed);
}

size_t sauron_memory_usage(sauron_ctx_t *ctx)
{
    if (ctx == NULL)
        return 0;
    return atomic_load_explicit(&ctx->memory_used, memory_order_relaxed);
}

/* Persistence */

/* Archive file format:
 * - Magic: "SAUR" (4 bytes)
 * - Version: 1 (4 bytes, little-endian)
 * - Entry count (8 bytes, little-endian)
 * - Entries: IP (4 bytes) + Score (2 bytes) each
 */
#define SAURON_MAGIC "SAUR"
#define SAURON_ARCHIVE_VERSION 1

#define WRITE_BUFFER_ENTRIES 4096
typedef struct {
    uint32_t ip;
    int16_t score;
} __attribute__((packed)) archive_entry_t;

int sauron_save(sauron_ctx_t *ctx, const char *filename)
{
    FILE *fp;
    char tmp_filename[PATH_MAX];
    uint32_t magic = *(uint32_t *)SAURON_MAGIC;
    uint32_t version = SAURON_ARCHIVE_VERSION;
    uint64_t actual_entry_count = 0;
    long count_offset;
    int prefix16, block_idx, host_idx;
    _Atomic(cidr_block_t *) *block_arr;
    cidr_block_t *block;
    uint32_t ip;
    int16_t score;
    /* P2: Buffered I/O */
    archive_entry_t write_buffer[WRITE_BUFFER_ENTRIES];
    size_t buffer_idx = 0;

    if (ctx == NULL || filename == NULL)
        return SAURON_ERR_NULL;

    /* Create temp filename */
    snprintf(tmp_filename, sizeof(tmp_filename), "%s.tmp.%d", filename, getpid());

    /* Open temp file */
    fp = fopen(tmp_filename, "wb");
    if (fp == NULL)
        return SAURON_ERR_IO;

    /* Write header */
    if (fwrite(&magic, sizeof(magic), 1, fp) != 1 ||
        fwrite(&version, sizeof(version), 1, fp) != 1) {
        fclose(fp);
        unlink(tmp_filename);
        return SAURON_ERR_IO;
    }

    count_offset = ftell(fp);
    actual_entry_count = 0;  /* Will be updated after counting actual entries */
    if (fwrite(&actual_entry_count, sizeof(actual_entry_count), 1, fp) != 1) {
        fclose(fp);
        unlink(tmp_filename);
        return SAURON_ERR_IO;
    }

    for (prefix16 = 0; prefix16 < PREFIX16_COUNT; prefix16++) {
        block_arr = ctx->block_ptrs[prefix16];
        if (block_arr == NULL)
            continue;

        for (block_idx = 0; block_idx < BLOCKS_PER_16; block_idx++) {
            block = atomic_load_explicit(&block_arr[block_idx], memory_order_acquire);
            if (block == NULL)
                continue;

            if (atomic_load_explicit(&block->active_count, memory_order_relaxed) == 0)
                continue;

            for (host_idx = 0; host_idx < SCORES_PER_BLOCK; host_idx++) {
                score = atomic_load_explicit(&block->scores[host_idx], memory_order_relaxed);
                if (score == 0)
                    continue;

                /* Reconstruct IP from prefix16, block_idx (prefix24 lower 8 bits), host_idx */
                ip = ((uint32_t)prefix16 << 16) | ((uint32_t)block_idx << 8) | (uint32_t)host_idx;

                write_buffer[buffer_idx].ip = ip;
                write_buffer[buffer_idx].score = score;
                buffer_idx++;
                actual_entry_count++;

                /* Flush buffer when full */
                if (buffer_idx >= WRITE_BUFFER_ENTRIES) {
                    if (fwrite(write_buffer, sizeof(archive_entry_t), buffer_idx, fp) != buffer_idx) {
                        fclose(fp);
                        unlink(tmp_filename);
                        return SAURON_ERR_IO;
                    }
                    buffer_idx = 0;
                }
            }
        }
    }

    /* Flush remaining buffer */
    if (buffer_idx > 0) {
        if (fwrite(write_buffer, sizeof(archive_entry_t), buffer_idx, fp) != buffer_idx) {
            fclose(fp);
            unlink(tmp_filename);
            return SAURON_ERR_IO;
        }
    }

    if (fseek(fp, count_offset, SEEK_SET) != 0) {
        fclose(fp);
        unlink(tmp_filename);
        return SAURON_ERR_IO;
    }
    if (fwrite(&actual_entry_count, sizeof(actual_entry_count), 1, fp) != 1) {
        fclose(fp);
        unlink(tmp_filename);
        return SAURON_ERR_IO;
    }

    /* Flush and sync */
    if (fflush(fp) != 0) {
        fclose(fp);
        unlink(tmp_filename);
        return SAURON_ERR_IO;
    }

#ifdef HAVE_FSYNC
    if (fsync(fileno(fp)) != 0) {
        fclose(fp);
        unlink(tmp_filename);
        return SAURON_ERR_IO;
    }
#endif

    fclose(fp);

    /* Atomic rename */
    if (rename(tmp_filename, filename) != 0) {
        unlink(tmp_filename);
        return SAURON_ERR_IO;
    }

    return SAURON_OK;
}

#define MAX_ARCHIVE_ENTRIES ((uint64_t)0x100000000ULL)

int sauron_load(sauron_ctx_t *ctx, const char *filename)
{
    FILE *fp;
    uint32_t magic, version;
    uint64_t entry_count, i;
    uint32_t ip;
    int16_t score;
    int prefix16, block_idx;
    _Atomic(cidr_block_t *) *block_arr;
    cidr_block_t *block;
    uint32_t prefix24;

    if (ctx == NULL || filename == NULL)
        return SAURON_ERR_NULL;

    /* Open file */
    fp = fopen(filename, "rb");
    if (fp == NULL)
        return SAURON_ERR_IO;

    /* Read and verify header */
    if (fread(&magic, sizeof(magic), 1, fp) != 1 ||
        fread(&version, sizeof(version), 1, fp) != 1) {
        fclose(fp);
        return SAURON_ERR_IO;
    }

    if (magic != *(uint32_t *)SAURON_MAGIC) {
        fclose(fp);
        return SAURON_ERR_INVALID;
    }

    if (version == 0 || version > SAURON_ARCHIVE_VERSION) {
        fclose(fp);
        return SAURON_ERR_INVALID;
    }

    /* Read entry count */
    if (fread(&entry_count, sizeof(entry_count), 1, fp) != 1) {
        fclose(fp);
        return SAURON_ERR_IO;
    }

    if (entry_count > MAX_ARCHIVE_ENTRIES) {
        fclose(fp);
        return SAURON_ERR_INVALID;
    }

    /* Clear existing scores (iterate all blocks and zero them) */
    for (prefix16 = 0; prefix16 < PREFIX16_COUNT; prefix16++) {
        block_arr = ctx->block_ptrs[prefix16];
        if (block_arr == NULL)
            continue;

        for (block_idx = 0; block_idx < BLOCKS_PER_16; block_idx++) {
            block = atomic_load_explicit(&block_arr[block_idx], memory_order_acquire);
            if (block == NULL)
                continue;

            prefix24 = ((uint32_t)prefix16 << 8) | (uint32_t)block_idx;

            SAURON_LOCK(&block->lock);
            memset((void *)block->scores, 0, sizeof(block->scores));
            atomic_store_explicit(&block->active_count, 0, memory_order_release);
            SAURON_UNLOCK(&block->lock);

            bitmap_clear(ctx, prefix24);
        }
    }
    atomic_store_explicit(&ctx->score_count, 0, memory_order_release);

    /* Read entries */
    for (i = 0; i < entry_count; i++) {
        if (fread(&ip, sizeof(ip), 1, fp) != 1 ||
            fread(&score, sizeof(score), 1, fp) != 1) {
            fclose(fp);
            return SAURON_ERR_IO;
        }

        /* Skip zero scores */
        if (score == 0)
            continue;

        sauron_set_u32(ctx, ip, score);
    }

    fclose(fp);
    return SAURON_OK;
}

/* Utility Functions */

uint32_t sauron_ip_to_u32(const char *ip)
{
    uint32_t result = 0;
    uint32_t octet = 0;
    int dots = 0;
    int digits_in_octet = 0;
    const char *p;

    if (ip == NULL)
        return 0;

    for (p = ip; *p != '\0'; p++) {
        if (*p >= '0' && *p <= '9') {
            octet = octet * 10 + (*p - '0');
            digits_in_octet++;
            if (octet > 255)
                return 0;  /* Invalid octet */
        } else if (*p == '.') {
            if (digits_in_octet == 0)
                return 0;
            if (dots >= 3)
                return 0;  /* Too many dots */
            result = (result << 8) | octet;
            octet = 0;
            digits_in_octet = 0;
            dots++;
        } else {
            return 0;  /* Invalid character */
        }
    }

    if (digits_in_octet == 0)
        return 0;

    if (dots != 3)
        return 0;  /* Not enough dots */

    result = (result << 8) | octet;

    return result;
}

void sauron_u32_to_ip(uint32_t ip, char *buf)
{
    if (buf == NULL)
        return;

    snprintf(buf, 16, "%u.%u.%u.%u",
             (ip >> 24) & 0xFF,
             (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF,
             ip & 0xFF);
}

int sauron_u32_to_ip_s(uint32_t ip, char *buf, size_t buf_size)
{
    if (buf == NULL || buf_size < 16)
        return 0;

    return snprintf(buf, buf_size, "%u.%u.%u.%u",
                    (ip >> 24) & 0xFF,
                    (ip >> 16) & 0xFF,
                    (ip >> 8) & 0xFF,
                    ip & 0xFF);
}

/* Extended Score Operations */

int sauron_get_ex(sauron_ctx_t *ctx, uint32_t ip, int16_t *score_out)
{
    cidr_block_t *block;
    uint8_t host_idx;
    int16_t score;

    if (ctx == NULL || score_out == NULL)
        return SAURON_ERR_NULL;

    block = get_block(ctx, ip);
    if (block == NULL) {
        *score_out = 0;
        return SAURON_ERR_INVALID;  /* Not found */
    }

    host_idx = ip_to_host_idx(ip);
    score = atomic_load_explicit(&block->scores[host_idx], memory_order_acquire);

    if (score == 0)
        return SAURON_ERR_INVALID;  /* Score is 0, treat as not found */

    *score_out = score;
    return SAURON_OK;
}

/* Clear and Iteration */

int sauron_clear(sauron_ctx_t *ctx)
{
    int prefix16, block_idx;
    _Atomic(cidr_block_t *) *block_arr;
    cidr_block_t *block;
    uint32_t prefix24;

    if (ctx == NULL)
        return SAURON_ERR_NULL;

    /* Clear all blocks */
    for (prefix16 = 0; prefix16 < PREFIX16_COUNT; prefix16++) {
        block_arr = ctx->block_ptrs[prefix16];
        if (block_arr == NULL)
            continue;

        for (block_idx = 0; block_idx < BLOCKS_PER_16; block_idx++) {
            block = atomic_load_explicit(&block_arr[block_idx], memory_order_acquire);
            if (block == NULL)
                continue;

            prefix24 = ((uint32_t)prefix16 << 8) | (uint32_t)block_idx;

            SAURON_LOCK(&block->lock);
            memset((void *)block->scores, 0, sizeof(block->scores));
            atomic_store_explicit(&block->active_count, 0, memory_order_release);
            SAURON_UNLOCK(&block->lock);

            /* Clear bitmap bit */
            bitmap_clear(ctx, prefix24);
        }
    }

    atomic_store_explicit(&ctx->score_count, 0, memory_order_release);
    return SAURON_OK;
}

uint64_t sauron_foreach(sauron_ctx_t *ctx, sauron_foreach_cb callback, void *user_data)
{
    uint64_t count = 0;
    int prefix16, block_idx, host_idx;
    _Atomic(cidr_block_t *) *block_arr;
    cidr_block_t *block;
    uint32_t ip, prefix24;
    int16_t score;
    int stop = 0;

    if (ctx == NULL || callback == NULL)
        return 0;

    for (prefix16 = 0; prefix16 < PREFIX16_COUNT && !stop; prefix16++) {
        block_arr = ctx->block_ptrs[prefix16];
        if (block_arr == NULL)
            continue;

        for (block_idx = 0; block_idx < BLOCKS_PER_16 && !stop; block_idx++) {
            /* Use bitmap to skip empty blocks */
            prefix24 = ((uint32_t)prefix16 << 8) | (uint32_t)block_idx;
            if (!bitmap_test(ctx, prefix24))
                continue;

            block = atomic_load_explicit(&block_arr[block_idx], memory_order_acquire);
            if (block == NULL)
                continue;

            if (atomic_load_explicit(&block->active_count, memory_order_relaxed) == 0)
                continue;

            /* Note: We don't lock during iteration for performance.
             * Scores may change during iteration - this is acceptable. */
            for (host_idx = 0; host_idx < SCORES_PER_BLOCK && !stop; host_idx++) {
                score = atomic_load_explicit(&block->scores[host_idx], memory_order_relaxed);
                if (score == 0)
                    continue;

                ip = ((uint32_t)prefix16 << 16) | ((uint32_t)block_idx << 8) | (uint32_t)host_idx;
                count++;

                if (callback(ip, score, user_data) != 0) {
                    stop = 1;
                }
            }
        }
    }

    return count;
}

const char *sauron_version(void)
{
    return SAURON_VERSION_STRING;
}
