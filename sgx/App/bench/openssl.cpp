/*
 * Created on Thu Feb 17 2023
 *
 * Copyright (c) 2022 Peterson Yuhala
 */

#include "headers.h"

// for benchmarking
#include "polydb/polydb.h"

#include "bench.h"

static struct timespec start, stop;
static double diff;

/**
 * globals for getting cpu stats
 */
static unsigned long long **cpu_stats_begin;
static unsigned long long **cpu_stats_end;

#define NUM_PTS 20

void run_openssl_bench(int num_runs)
{

    // todo: do this neatly..change the function signature
    char cmd[20];
    snprintf(cmd, 20, "rm results_openssl*");
    remove_old_results(cmd);

    char path[20];
    snprintf(path, 20, "results_openssl.csv");

    printf(">>>>>>>>>>>>>>>>> lmbench bench START >>>>>>>>>>>>>>>>>\n");
    int min_bytes = 1024; // minimum number of bytes to read/encrypt/decrypt
    int max_bytes = 256 * 1024;
    //int max_bytes = (16 * 1024 * 1024); // maximum number of bytes to read/encrypt/decrypt
    int step = (int)(max_bytes / NUM_POINTS);

    double total_runtime;
    double avg_runtime;
    double tput;
    double cpu_usage;
    double avg_cpu;

    for (int i = min_bytes; i <= max_bytes; i += step)
    {

        total_runtime = 0;
        avg_runtime = 0;
        cpu_usage = 0;
        for (int j = 0; j < num_runs; j++)
        {
            start_clock(&start);

            cpu_stats_begin = read_cpu();
            openssl_bench(i);
            cpu_stats_end = read_cpu();

            stop_clock(&stop);
            total_runtime += time_diff(&start, &stop, SEC);
            cpu_usage += get_avg_cpu_usage(cpu_stats_end, cpu_stats_begin);

            free(cpu_stats_begin);
            free(cpu_stats_end);
        }
        avg_runtime = total_runtime / num_runs;
        tput = i / avg_runtime; // ops/sec
        avg_cpu = cpu_usage / num_runs;

        register_results(path, i, avg_runtime, tput, avg_cpu);
        printf(">>>>>>>>>>>>>>>>> OpenSSL bench: max_bytes: %d COMPLETE >>>>>>>>>>>>>>>>>\n", i);
    }
    printf(">>>>>>>>>>>>>>>>> OpenSSL bench END >>>>>>>>>>>>>>>>>\n");
}
