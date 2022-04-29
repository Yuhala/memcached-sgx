/*
 * Created on Thu Apr 21 2022
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

void run_lmbench(int num_runs)
{

    // todo: do this neatly..change the function signature
    char cmd[20];
    snprintf(cmd, 20, "rm results_lmbench*");
    remove_old_results(cmd);

    char path[20];
    snprintf(path, 20, "results_lmbench.csv");

    printf(">>>>>>>>>>>>>>>>> lmbench bench START >>>>>>>>>>>>>>>>>\n");
    int min_ops = 5000;
    int max_ops = 100000;
    int step = 5000;
    int num_threads = 2;

    double total_runtime;
    double avg_runtime;
    double tput;
    double cpu_usage;
    double avg_cpu;

    for (int i = min_ops; i <= max_ops; i += step)
    {

        total_runtime = 0;
        avg_runtime = 0;
        cpu_usage = 0;
        for (int j = 0; j < num_runs; j++)
        {
            start_clock(&start);

            cpu_stats_begin = read_cpu();
            lmbench_simple(i, num_threads);
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
        printf(">>>>>>>>>>>>>>>>> Lmbench bench: num-ops: %d COMPLETE >>>>>>>>>>>>>>>>>\n", i);
    }
    printf(">>>>>>>>>>>>>>>>> Lmbench END >>>>>>>>>>>>>>>>>\n");
}

/**
 * remove old results
 */
void remove_old_results(const char *cmd)
{
    printf(">>>>>>>>>>>>>>removing old results: %s >>>>>>>>>>>>>>>>>\n", cmd);
    int ret = system(cmd);
    // ZC_ASSERT(!ret);
}
