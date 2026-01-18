/* Rigorous benchmark for bulk load with full verification */
#define _POSIX_C_SOURCE 199309L  /* For clock_gettime */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sauron.h>

/* Store expected values for verification */
typedef struct {
    uint32_t ip;
    int16_t expected_score;
} expected_entry_t;

static double get_time(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Generate unique IP from index - guaranteed no collisions */
static uint32_t index_to_ip(int i)
{
    /* Use a simple scheme: start from 1.0.0.1 and increment */
    uint32_t ip = 0x01000001 + (uint32_t)i;  /* Start at 1.0.0.1 */

    /* Skip reserved range (240+) to avoid wraparound */
    if ((ip >> 24) >= 240) {
        return 0;  /* Invalid - we've run out of IPs */
    }

    return ip;
}

int main(int argc, char **argv)
{
    int count = 100000;  /* 100K default for full verification */
    if (argc > 1)
        count = atoi(argv[1]);

    printf("Bulk Load Verification Benchmark\n");
    printf("=================================\n\n");

    /* Allocate array for expected values */
    expected_entry_t *expected = malloc(count * sizeof(expected_entry_t));
    if (!expected) {
        fprintf(stderr, "Cannot allocate expected array\n");
        return 1;
    }

    printf("Phase 1: Generating %d line test file with unique IPs...\n", count);
    double gen_start = get_time();

    FILE *fp = fopen("/tmp/bulk_bench_verify.csv", "w");
    if (!fp) {
        fprintf(stderr, "Cannot create test file\n");
        return 1;
    }

    int valid_count = 0;
    
    for (int i = 0; i < count; i++) {
        uint32_t ip = index_to_ip(i);
        if (ip == 0) {
            fprintf(stderr, "Ran out of valid IPs at index %d\n", i);
            break;
        }

        /* Generate deterministic score based on index - never 0 */
        /* Range: -32767 to -1 and 1 to 32767 (skipping 0) */
        int32_t raw = (valid_count % 65534) - 32767;  /* -32767 to 32766 */
        int16_t score = (int16_t)(raw >= 0 ? raw + 1 : raw);  /* Skip 0 */
        
        /* Format IP */
        int a = (ip >> 24) & 0xFF;
        int b = (ip >> 16) & 0xFF;
        int c = (ip >> 8) & 0xFF;
        int d = ip & 0xFF;
        
        fprintf(fp, "%d.%d.%d.%d,%d\n", a, b, c, d, score);
        
        expected[valid_count].ip = ip;
        expected[valid_count].expected_score = score;
        valid_count++;
        
        if (valid_count >= (argc > 1 ? atoi(argv[1]) : 100000))
            break;
    }
    fclose(fp);
    
    count = valid_count;  /* Actual count */
    double gen_time = get_time() - gen_start;
    printf("  Valid entries generated: %d\n", count);
    printf("  Generation time: %.3f seconds\n", gen_time);

    /* Get file size */
    fp = fopen("/tmp/bulk_bench_verify.csv", "r");
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fclose(fp);
    printf("  File size: %.2f MB\n", file_size / (1024.0 * 1024.0));

    printf("\nPhase 2: Loading via sauron_bulk_load...\n");
    
    sauron_ctx_t *ctx = sauron_create();
    sauron_bulk_result_t result;

    double load_start = get_time();
    int ret = sauron_bulk_load(ctx, "/tmp/bulk_bench_verify.csv", &result);
    double load_time = get_time() - load_start;

    if (ret != 0) {
        fprintf(stderr, "Bulk load failed with code %d\n", ret);
        return 1;
    }

    printf("  Load time (reported): %.3f seconds\n", result.elapsed_seconds);
    printf("  Load time (measured): %.3f seconds\n", load_time);
    printf("  Lines processed: %lu\n", (unsigned long)result.lines_processed);
    printf("  Sets: %lu\n", (unsigned long)result.sets);
    printf("  Updates: %lu\n", (unsigned long)result.updates);
    printf("  Skipped: %lu\n", (unsigned long)result.lines_skipped);
    printf("  Parse errors: %lu\n", (unsigned long)result.parse_errors);
    printf("  Rate: %.0f lines/second\n", result.lines_per_second);
    
    uint64_t actual_count = sauron_count(ctx);
    printf("  Score count in engine: %lu\n", (unsigned long)actual_count);

    if ((uint64_t)count != actual_count) {
        printf("  WARNING: Count mismatch! Expected %d, got %lu\n", 
               count, (unsigned long)actual_count);
    }

    printf("\nPhase 3: Verifying EVERY entry...\n");
    double verify_start = get_time();
    
    int verify_errors = 0;
    int verified = 0;
    
    for (int i = 0; i < count; i++) {
        uint32_t ip = expected[i].ip;
        int16_t expected_score = expected[i].expected_score;
        
        int16_t actual_score = sauron_get_u32(ctx, ip);
        
        if (actual_score != expected_score) {
            if (verify_errors < 10) {
                char ip_str[16];
                sauron_u32_to_ip(ip, ip_str);
                printf("  MISMATCH [%d] %s: expected %d, got %d\n", 
                       i, ip_str, expected_score, actual_score);
            }
            verify_errors++;
        } else {
            verified++;
        }
    }
    
    double verify_time = get_time() - verify_start;

    printf("  Verification time: %.3f seconds\n", verify_time);
    printf("  Verified correct: %d / %d\n", verified, count);
    printf("  Mismatches: %d\n", verify_errors);

    printf("\nPhase 4: Spot-check random access pattern...\n");
    double spot_start = get_time();
    int spot_checks = 10000;
    int spot_errors = 0;
    
    for (int i = 0; i < spot_checks; i++) {
        int idx = (i * 97 + 13) % count;  /* Pseudo-random but deterministic */
        uint32_t ip = expected[idx].ip;
        int16_t expected_score = expected[idx].expected_score;
        int16_t actual_score = sauron_get_u32(ctx, ip);
        
        if (actual_score != expected_score)
            spot_errors++;
    }
    double spot_time = get_time() - spot_start;
    printf("  Spot checks: %d in %.6f seconds (%.0f checks/sec)\n", 
           spot_checks, spot_time, spot_checks / spot_time);
    printf("  Spot check errors: %d\n", spot_errors);

    printf("\n=================================\n");
    printf("SUMMARY\n");
    printf("=================================\n");
    printf("  Entries:            %d\n", count);
    printf("  File size:          %.2f MB\n", file_size / (1024.0 * 1024.0));
    printf("  File generation:    %.3f sec\n", gen_time);
    printf("  Bulk load:          %.3f sec\n", load_time);
    printf("  Load rate:          %.0f lines/sec\n", count / load_time);
    printf("  Full verification:  %.3f sec\n", verify_time);
    printf("  Verify rate:        %.0f checks/sec\n", count / verify_time);
    printf("  Total errors:       %d\n", verify_errors + spot_errors);
    printf("  Accuracy:           %.4f%%\n", 100.0 * verified / count);
    
    int pass = (verify_errors == 0 && spot_errors == 0 && 
                (uint64_t)count == actual_count);
    
    if (pass) {
        printf("\n  RESULT: PASS - All %d entries verified correct\n", count);
    } else {
        printf("\n  RESULT: FAIL - Verification errors detected\n");
    }

    sauron_destroy(ctx);
    free(expected);
    unlink("/tmp/bulk_bench_verify.csv");

    return pass ? 0 : 1;
}
