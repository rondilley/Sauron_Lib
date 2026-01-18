/****
 *
 * Sauron - High-Speed IPv4 Scoring Engine
 * Command Line Interface
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

/****
 *
 * includes
 *
 ****/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../include/sysdep.h"
#include "../include/common.h"
#include "../include/sauron.h"
#include <time.h>

/****
 *
 * defines
 *
 ****/

#define PROGNAME "sauron-cli"

/****
 *
 * external variables (from libsauron)
 *
 ****/

extern Config_t *config;
extern int quit;

/****
 *
 * function prototypes
 *
 ****/

static void show_version(void);
static void show_usage(void);
static int init_config(void);
static void cleanup(void);

/****
 *
 * functions
 *
 ****/

/****
 *
 * show version info
 *
 ****/

static void show_version(void)
{
    printf("%s v%s\n", PROGNAME, sauron_version());
    printf("High-Speed IPv4 Scoring Engine CLI\n");
    printf("Copyright (c) 2024-2026, Ron Dilley\n");
}

/****
 *
 * show usage info
 *
 ****/

static void show_usage(void)
{
    printf("Usage: %s [options] <command> [args]\n", PROGNAME);
    printf("\n");
    printf("Options:\n");
    printf("  -h, --help       Show this help message\n");
    printf("  -v, --version    Show version information\n");
    printf("  -d, --debug      Enable debug output\n");
    printf("  -f FILE          Archive file to load/save\n");
    printf("\n");
    printf("Commands:\n");
    printf("  get <ip>                Get score for IP address\n");
    printf("  set <ip> <score>        Set score for IP address\n");
    printf("  incr <ip> <delta>       Increment score for IP address\n");
    printf("  decr <ip> <delta>       Decrement score for IP address\n");
    printf("  delete <ip>             Delete score for IP address\n");
    printf("  decay <factor> <dead>   Apply decay to all scores\n");
    printf("  stats                   Show statistics\n");
    printf("  load <file>             Load scores from archive\n");
    printf("  save <file>             Save scores to archive\n");
    printf("  benchmark [count]       Run performance benchmark\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s get 192.168.1.1\n", PROGNAME);
    printf("  %s set 10.0.0.1 100\n", PROGNAME);
    printf("  %s incr 172.16.0.1 10\n", PROGNAME);
    printf("  %s -f scores.dat stats\n", PROGNAME);
    printf("\n");
}

/****
 *
 * initialize config
 *
 ****/

static int init_config(void)
{
    /* config is provided by libsauron, just update fields */
    config->mode = MODE_INTERACTIVE;
    config->debug = FALSE;
    config->cur_pid = getpid();

    return TRUE;
}

/****
 *
 * cleanup
 *
 ****/

static void cleanup(void)
{
    /* config is owned by libsauron, nothing to free */
}

/****
 *
 * main
 *
 ****/

int main(int argc, char *argv[])
{
    int opt;
    int ret = EXIT_SUCCESS;
    char *archive_file = NULL;
    sauron_ctx_t *ctx = NULL;

    /* Initialize config */
    if (init_config() != TRUE) {
        return EXIT_FAILURE;
    }

    /* Parse command line options */
    while ((opt = getopt(argc, argv, "hvdf:")) != -1) {
        switch (opt) {
            case 'h':
                show_usage();
                cleanup();
                return EXIT_SUCCESS;

            case 'v':
                show_version();
                cleanup();
                return EXIT_SUCCESS;

            case 'd':
                config->debug = TRUE;
                break;

            case 'f':
                archive_file = optarg;
                break;

            default:
                show_usage();
                cleanup();
                return EXIT_FAILURE;
        }
    }

    /* Check for command */
    if (optind >= argc) {
        fprintf(stderr, "ERR - No command specified\n");
        show_usage();
        cleanup();
        return EXIT_FAILURE;
    }

    /* Create scoring engine context */
    ctx = sauron_create();
    if (ctx == NULL) {
        fprintf(stderr, "ERR - Failed to create scoring engine\n");
        cleanup();
        return EXIT_FAILURE;
    }

    /* Load archive if specified */
    if (archive_file != NULL) {
        if (sauron_load(ctx, archive_file) != SAURON_OK) {
            fprintf(stderr, "WARN - Failed to load archive: %s\n", archive_file);
        }
    }

    /* Process command */
    const char *cmd = argv[optind];

    if (strcmp(cmd, "get") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "ERR - get requires IP address\n");
            ret = EXIT_FAILURE;
        } else {
            int16_t score = sauron_get(ctx, argv[optind + 1]);
            printf("%s: %d\n", argv[optind + 1], score);
        }

    } else if (strcmp(cmd, "set") == 0) {
        if (optind + 2 >= argc) {
            fprintf(stderr, "ERR - set requires IP address and score\n");
            ret = EXIT_FAILURE;
        } else {
            int16_t score = (int16_t)atoi(argv[optind + 2]);
            int16_t old = sauron_set(ctx, argv[optind + 1], score);
            printf("%s: %d -> %d\n", argv[optind + 1], old, score);
        }

    } else if (strcmp(cmd, "incr") == 0) {
        if (optind + 2 >= argc) {
            fprintf(stderr, "ERR - incr requires IP address and delta\n");
            ret = EXIT_FAILURE;
        } else {
            int16_t delta = (int16_t)atoi(argv[optind + 2]);
            int16_t new_score = sauron_incr(ctx, argv[optind + 1], delta);
            printf("%s: %d\n", argv[optind + 1], new_score);
        }

    } else if (strcmp(cmd, "decr") == 0) {
        if (optind + 2 >= argc) {
            fprintf(stderr, "ERR - decr requires IP address and delta\n");
            ret = EXIT_FAILURE;
        } else {
            int16_t delta = (int16_t)atoi(argv[optind + 2]);
            int16_t new_score = sauron_decr(ctx, argv[optind + 1], delta);
            printf("%s: %d\n", argv[optind + 1], new_score);
        }

    } else if (strcmp(cmd, "delete") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "ERR - delete requires IP address\n");
            ret = EXIT_FAILURE;
        } else {
            int rc = sauron_delete(ctx, argv[optind + 1]);
            if (rc == SAURON_OK) {
                printf("%s: deleted\n", argv[optind + 1]);
            } else {
                printf("%s: delete failed (%d)\n", argv[optind + 1], rc);
            }
        }

    } else if (strcmp(cmd, "stats") == 0) {
        printf("Sauron IPv4 Scoring Engine v%s\n", sauron_version());
        printf("Active scores:    %lu\n", (unsigned long)sauron_count(ctx));
        printf("Allocated blocks: %lu\n", (unsigned long)sauron_block_count(ctx));
        printf("Memory usage:     %lu bytes\n", (unsigned long)sauron_memory_usage(ctx));

    } else if (strcmp(cmd, "decay") == 0) {
        if (optind + 2 >= argc) {
            fprintf(stderr, "ERR - decay requires factor and deadzone\n");
            ret = EXIT_FAILURE;
        } else {
            float factor = (float)atof(argv[optind + 1]);
            int16_t deadzone = (int16_t)atoi(argv[optind + 2]);
            uint64_t modified = sauron_decay(ctx, factor, deadzone);
            printf("Decay complete: %lu scores modified\n", (unsigned long)modified);
        }

    } else if (strcmp(cmd, "load") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "ERR - load requires filename\n");
            ret = EXIT_FAILURE;
        } else {
            int rc = sauron_load(ctx, argv[optind + 1]);
            if (rc == SAURON_OK) {
                printf("Loaded: %s\n", argv[optind + 1]);
            } else {
                printf("Load failed: %s (%d)\n", argv[optind + 1], rc);
                ret = EXIT_FAILURE;
            }
        }

    } else if (strcmp(cmd, "save") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "ERR - save requires filename\n");
            ret = EXIT_FAILURE;
        } else {
            int rc = sauron_save(ctx, argv[optind + 1]);
            if (rc == SAURON_OK) {
                printf("Saved: %s\n", argv[optind + 1]);
            } else {
                printf("Save failed: %s (%d)\n", argv[optind + 1], rc);
                ret = EXIT_FAILURE;
            }
        }

    } else if (strcmp(cmd, "benchmark") == 0) {
        uint64_t count = 1000000;  /* Default 1M operations */
        if (optind + 1 < argc) {
            count = (uint64_t)atoll(argv[optind + 1]);
        }

        printf("Sauron Benchmark - %lu operations\n", (unsigned long)count);
        printf("================================================\n\n");

        struct timespec start, end;
        double elapsed;

        /* Benchmark: Sequential writes to different /24 blocks */
        printf("SET (random /24 blocks):\n");
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (uint64_t i = 0; i < count; i++) {
            uint32_t ip = (uint32_t)((i & 0xFFFF) << 16) | (uint32_t)(i & 0xFF);
            sauron_set_u32(ctx, ip, (int16_t)(i & 0x7FFF));
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        printf("  Time: %.3f sec, Ops/sec: %.0f\n\n", elapsed, count / elapsed);

        /* Benchmark: Sequential reads */
        printf("GET (random /24 blocks):\n");
        volatile int16_t sink = 0;
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (uint64_t i = 0; i < count; i++) {
            uint32_t ip = (uint32_t)((i & 0xFFFF) << 16) | (uint32_t)(i & 0xFF);
            sink = sauron_get_u32(ctx, ip);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        printf("  Time: %.3f sec, Ops/sec: %.0f\n\n", elapsed, count / elapsed);
        (void)sink;

        /* Benchmark: Increment operations (same IPs) */
        printf("INCR (sequential same block):\n");
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (uint64_t i = 0; i < count; i++) {
            uint32_t ip = 0xC0A80000 | (uint32_t)(i & 0xFF);  /* 192.168.0.x */
            sauron_incr_u32(ctx, ip, 1);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        printf("  Time: %.3f sec, Ops/sec: %.0f\n\n", elapsed, count / elapsed);

        /* Statistics */
        printf("Final Statistics:\n");
        printf("  Active scores:    %lu\n", (unsigned long)sauron_count(ctx));
        printf("  Allocated blocks: %lu\n", (unsigned long)sauron_block_count(ctx));
        printf("  Memory usage:     %lu bytes\n", (unsigned long)sauron_memory_usage(ctx));

    } else {
        fprintf(stderr, "ERR - Unknown command: %s\n", cmd);
        show_usage();
        ret = EXIT_FAILURE;
    }

    /* Save archive if specified and command succeeded */
    if (archive_file != NULL && ret == EXIT_SUCCESS) {
        if (strcmp(cmd, "set") == 0 || strcmp(cmd, "incr") == 0 ||
            strcmp(cmd, "decr") == 0 || strcmp(cmd, "delete") == 0 ||
            strcmp(cmd, "decay") == 0) {
            if (sauron_save(ctx, archive_file) != SAURON_OK) {
                fprintf(stderr, "WARN - Failed to save archive: %s\n", archive_file);
            }
        }
    }

    /* Cleanup */
    sauron_destroy(ctx);
    cleanup();

    return ret;
}
