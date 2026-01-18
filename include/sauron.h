/****
 *
 * Sauron - High-Speed IPv4 Scoring Engine
 * Public API Header
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

#ifndef SAURON_H
#define SAURON_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

/****
 *
 * Version Information
 * (SAURON_VERSION_MAJOR, SAURON_VERSION_MINOR, SAURON_VERSION_PATCH
 *  are defined in config.h from m4/version.m4)
 *
 ****/

#define SAURON_VERSION_STRING PACKAGE_VERSION

/****
 *
 * Error Codes
 *
 ****/

#define SAURON_OK           0
#define SAURON_ERR_NULL    -1   /* NULL pointer argument */
#define SAURON_ERR_INVALID -2   /* Invalid argument */
#define SAURON_ERR_NOMEM   -3   /* Memory allocation failed */
#define SAURON_ERR_IO      -4   /* I/O error */

/****
 *
 * Score Limits
 *
 ****/

#define SAURON_SCORE_MIN    (-32767)
#define SAURON_SCORE_MAX    (32767)
#define SAURON_SCORE_NEUTRAL 0

/****
 *
 * Opaque Context Type
 *
 ****/

typedef struct sauron_ctx sauron_ctx_t;

/****
 *
 * Lifecycle Functions
 *
 ****/

/**
 * Create a new scoring engine context.
 *
 * @return Pointer to context, or NULL on failure (aborts on OOM)
 */
sauron_ctx_t *sauron_create(void);

/**
 * Destroy a scoring engine context and free all resources.
 *
 * @param ctx Context to destroy (may be NULL)
 */
void sauron_destroy(sauron_ctx_t *ctx);

/****
 *
 * Score Operations (uint32_t IP - Fast Path)
 *
 ****/

/**
 * Get the score for an IP address.
 *
 * @param ctx Scoring engine context
 * @param ip  IPv4 address in host byte order
 * @return Score value, or 0 if not found
 */
int16_t sauron_get_u32(sauron_ctx_t *ctx, uint32_t ip);

/**
 * Set the score for an IP address.
 *
 * @param ctx   Scoring engine context
 * @param ip    IPv4 address in host byte order
 * @param score Score value to set
 * @return Previous score value, or 0 if new entry
 */
int16_t sauron_set_u32(sauron_ctx_t *ctx, uint32_t ip, int16_t score);

/**
 * Increment the score for an IP address (saturating).
 *
 * @param ctx   Scoring engine context
 * @param ip    IPv4 address in host byte order
 * @param delta Amount to add (positive or negative)
 * @return New score value after increment
 */
int16_t sauron_incr_u32(sauron_ctx_t *ctx, uint32_t ip, int16_t delta);

/**
 * Decrement the score for an IP address (saturating).
 * Equivalent to sauron_incr_u32(ctx, ip, -delta).
 *
 * @param ctx   Scoring engine context
 * @param ip    IPv4 address in host byte order
 * @param delta Amount to subtract
 * @return New score value after decrement
 */
int16_t sauron_decr_u32(sauron_ctx_t *ctx, uint32_t ip, int16_t delta);

/**
 * Delete the score for an IP address (set to 0).
 *
 * @param ctx Scoring engine context
 * @param ip  IPv4 address in host byte order
 * @return SAURON_OK on success, error code on failure
 */
int sauron_delete_u32(sauron_ctx_t *ctx, uint32_t ip);

/****
 *
 * Score Operations (String IP)
 *
 ****/

/**
 * Get the score for an IP address (string form).
 *
 * @param ctx Scoring engine context
 * @param ip  IPv4 address as dotted-decimal string
 * @return Score value, or 0 if not found/invalid
 */
int16_t sauron_get(sauron_ctx_t *ctx, const char *ip);

/**
 * Set the score for an IP address (string form).
 *
 * @param ctx   Scoring engine context
 * @param ip    IPv4 address as dotted-decimal string
 * @param score Score value to set
 * @return Previous score value, or 0 if new entry/invalid
 */
int16_t sauron_set(sauron_ctx_t *ctx, const char *ip, int16_t score);

/**
 * Increment the score for an IP address (string form).
 *
 * @param ctx   Scoring engine context
 * @param ip    IPv4 address as dotted-decimal string
 * @param delta Amount to add
 * @return New score value, or 0 if invalid
 */
int16_t sauron_incr(sauron_ctx_t *ctx, const char *ip, int16_t delta);

/**
 * Decrement the score for an IP address (string form).
 *
 * @param ctx   Scoring engine context
 * @param ip    IPv4 address as dotted-decimal string
 * @param delta Amount to subtract
 * @return New score value, or 0 if invalid
 */
int16_t sauron_decr(sauron_ctx_t *ctx, const char *ip, int16_t delta);

/**
 * Delete the score for an IP address (string form).
 *
 * @param ctx Scoring engine context
 * @param ip  IPv4 address as dotted-decimal string
 * @return SAURON_OK on success, error code on failure
 */
int sauron_delete(sauron_ctx_t *ctx, const char *ip);

/****
 *
 * Batch Operations
 *
 ****/

/**
 * Increment scores for multiple IP addresses.
 *
 * @param ctx    Scoring engine context
 * @param ips    Array of IPv4 addresses in host byte order
 * @param deltas Array of delta values (one per IP)
 * @param count  Number of elements in arrays
 * @return Number of successful increments
 */
int sauron_incr_batch(sauron_ctx_t *ctx, const uint32_t *ips,
                      const int16_t *deltas, size_t count);

/****
 *
 * Bulk File Loading
 *
 ****/

/**
 * Result structure for bulk load operations.
 * Contains statistics and timing information.
 */
typedef struct sauron_bulk_result {
    uint64_t lines_processed;   /* Total lines read from file */
    uint64_t lines_skipped;     /* Lines skipped (invalid, parse errors) */
    uint64_t sets;              /* Absolute sets performed (e.g., "100") */
    uint64_t updates;           /* Relative updates performed (e.g., "+10", "-5") */
    uint64_t parse_errors;      /* Lines with parse errors */
    double elapsed_seconds;     /* Total time for operation */
    double lines_per_second;    /* Processing rate */
} sauron_bulk_result_t;

/**
 * Bulk load IP score changes from a CSV file.
 *
 * File format: one entry per line, comma-separated:
 *   IP,CHANGE
 *
 * Where:
 *   IP     = IPv4 address in dotted-decimal notation (e.g., "192.168.1.1")
 *   CHANGE = Score change, one of:
 *            - Absolute value: "100" (sets score to 100)
 *            - Negative absolute: "-25" (sets score to -25)
 *            - Relative increment: "+10" (adds 10 to current score)
 *            - Relative decrement: "+-5" (subtracts 5 from current score)
 *
 * Note: Only the "+" prefix indicates a relative update. A bare "-N" is
 * an absolute set to a negative value. Use "+-N" for relative decrements.
 *
 * Example file:
 *   192.168.1.1,100      # Set to 100
 *   192.168.1.2,+50      # Add 50 to current score
 *   10.0.0.1,-25         # Set to -25 (negative score)
 *   10.0.0.2,+-10        # Subtract 10 from current score
 *
 * Lines starting with '#' are comments. Empty lines are skipped.
 *
 * @param ctx      Scoring engine context
 * @param filename Path to CSV file
 * @param result   Optional pointer to receive statistics (may be NULL)
 * @return SAURON_OK on success, error code on failure
 */
int sauron_bulk_load(sauron_ctx_t *ctx, const char *filename,
                     sauron_bulk_result_t *result);

/**
 * Bulk load IP score changes from a memory buffer.
 * Same format as sauron_bulk_load() but reads from memory.
 *
 * @param ctx    Scoring engine context
 * @param data   Buffer containing CSV data
 * @param len    Length of buffer in bytes
 * @param result Optional pointer to receive statistics (may be NULL)
 * @return SAURON_OK on success, error code on failure
 */
int sauron_bulk_load_buffer(sauron_ctx_t *ctx, const char *data, size_t len,
                            sauron_bulk_result_t *result);

/****
 *
 * Decay
 *
 ****/

/**
 * Apply decay to all scores.
 * Scores are multiplied by decay_factor and moved toward 0.
 * Scores within deadzone of 0 are deleted.
 *
 * @param ctx          Scoring engine context
 * @param decay_factor Multiplication factor (0.0-1.0, e.g., 0.9)
 * @param deadzone     Absolute value threshold for deletion
 * @return Number of scores modified/deleted
 */
uint64_t sauron_decay(sauron_ctx_t *ctx, float decay_factor, int16_t deadzone);

/****
 *
 * Statistics
 *
 ****/

/**
 * Get count of active scores (non-zero).
 *
 * @param ctx Scoring engine context
 * @return Number of active scores
 */
uint64_t sauron_count(sauron_ctx_t *ctx);

/**
 * Get count of allocated CIDR blocks.
 *
 * @param ctx Scoring engine context
 * @return Number of allocated blocks
 */
uint64_t sauron_block_count(sauron_ctx_t *ctx);

/**
 * Get current memory usage.
 *
 * @param ctx Scoring engine context
 * @return Memory usage in bytes
 */
size_t sauron_memory_usage(sauron_ctx_t *ctx);

/****
 *
 * Persistence
 *
 ****/

/**
 * Save scores to a binary archive file.
 *
 * @param ctx      Scoring engine context
 * @param filename Path to archive file
 * @return SAURON_OK on success, error code on failure
 */
int sauron_save(sauron_ctx_t *ctx, const char *filename);

/**
 * Load scores from a binary archive file.
 *
 * @param ctx      Scoring engine context
 * @param filename Path to archive file
 * @return SAURON_OK on success, error code on failure
 */
int sauron_load(sauron_ctx_t *ctx, const char *filename);

/****
 *
 * Extended Score Operations
 *
 ****/

/**
 * Get the score for an IP address with explicit error reporting.
 * Unlike sauron_get_u32(), this function distinguishes between
 * "score is 0" and "error/not found".
 *
 * @param ctx       Scoring engine context
 * @param ip        IPv4 address in host byte order
 * @param score_out Pointer to receive the score value
 * @return SAURON_OK if score found and written to score_out,
 *         SAURON_ERR_NULL if ctx or score_out is NULL,
 *         SAURON_ERR_INVALID if IP not found (score would be 0)
 */
int sauron_get_ex(sauron_ctx_t *ctx, uint32_t ip, int16_t *score_out);

/****
 *
 * Clear and Iteration
 *
 ****/

/**
 * Clear all scores without destroying the context.
 * More efficient than destroy/create cycle.
 *
 * @param ctx Scoring engine context
 * @return SAURON_OK on success, SAURON_ERR_NULL if ctx is NULL
 */
int sauron_clear(sauron_ctx_t *ctx);

/**
 * Callback function type for iteration.
 *
 * @param ip        IPv4 address in host byte order
 * @param score     Score value for this IP
 * @param user_data User-provided context pointer
 * @return 0 to continue iteration, non-zero to stop early
 */
typedef int (*sauron_foreach_cb)(uint32_t ip, int16_t score, void *user_data);

/**
 * Iterate over all scored IP addresses.
 * Calls the callback for each IP with a non-zero score.
 *
 * Note: The callback is called while holding block locks. Do not call
 * other sauron functions from within the callback to avoid deadlocks.
 *
 * @param ctx       Scoring engine context
 * @param callback  Function to call for each scored IP
 * @param user_data User context passed to callback
 * @return Number of IPs iterated, or 0 on error
 */
uint64_t sauron_foreach(sauron_ctx_t *ctx, sauron_foreach_cb callback, void *user_data);

/****
 *
 * Utility Functions
 *
 ****/

/**
 * Parse an IPv4 address string to uint32_t.
 *
 * @param ip IPv4 address as dotted-decimal string
 * @return IP in host byte order, or 0 on invalid input
 */
uint32_t sauron_ip_to_u32(const char *ip);

/**
 * Format a uint32_t IP address as a string.
 *
 * @param ip  IPv4 address in host byte order
 * @param buf Buffer to write to (must be at least 16 bytes)
 * @deprecated Use sauron_u32_to_ip_s() for safer buffer handling
 */
void sauron_u32_to_ip(uint32_t ip, char *buf);

/**
 * Format a uint32_t IP address as a string (safe version).
 *
 * @param ip       IPv4 address in host byte order
 * @param buf      Buffer to write to
 * @param buf_size Size of buffer (must be at least 16 for full IP)
 * @return Number of characters written (excluding null), or 0 on error
 */
int sauron_u32_to_ip_s(uint32_t ip, char *buf, size_t buf_size);

/**
 * Get version string.
 *
 * @return Version string (e.g., "0.1.0")
 */
const char *sauron_version(void);

#ifdef __cplusplus
}
#endif

#endif /* SAURON_H */
