/*
 * Created on Thu Apr 21 2022
 *
 * Copyright (c) 2022 Peterson Yuhala
 */

#include "headers.h"


//for benchmarking
#include "polydb/polydb.h"


static struct timespec start, stop;
static double diff;

/**
 * globals for getting cpu stats
 */
static unsigned long long **cpu_stats_begin;
static unsigned long long **cpu_stats_end;
/**
 * remove all kyoto cabinet dbs
 */
void remove_kc_dbs()
{
    //printf(">>>>>>>>>>>>>>..removing kissdb files..>>>>>>>>>>>>>>>>>\n");
    int ret = system("rm *.kcd");
    ZC_ASSERT(!ret);
}


void run_kyoto_bench(int num_runs)
{

    char path[20];
    snprintf(path, 20, "results_kyoto.csv");

    printf(">>>>>>>>>>>>>>>>> kyoto bench START >>>>>>>>>>>>>>>>>\n");
    int min_keys = 500;
    int max_keys = 10000;
    int step = 500;
    int num_writers = 2;

    double total_runtime;
    double avg_runtime;
    double tput;
    double cpu_usage;
    double avg_cpu;

    for (int i = min_keys; i <= max_keys; i += step)
    {

        total_runtime = 0;
        avg_runtime = 0;
        cpu_usage = 0;
        for (int j = 0; j < num_runs; j++)
        {
            start_clock(&start);

            cpu_stats_begin = read_cpu();
            write_keys(i, num_writers);
            cpu_stats_end = read_cpu();

            stop_clock(&stop);
            total_runtime += time_diff(&start, &stop, SEC);
            cpu_usage += get_avg_cpu_usage(cpu_stats_end, cpu_stats_begin);

            free(cpu_stats_begin);
            free(cpu_stats_end);
            remove_kc_dbs();
        }
        avg_runtime = total_runtime / num_runs;
        tput = i / avg_runtime; // ops/sec
        avg_cpu = cpu_usage / num_runs;

        register_results(path, i, avg_runtime, tput, avg_cpu);
        printf(">>>>>>>>>>>>>>>>> kyoto bench: SET %d keys COMPLETE >>>>>>>>>>>>>>>>>\n", i);
    }
    printf(">>>>>>>>>>>>>>>>> kyoto bench END >>>>>>>>>>>>>>>>>\n");
}
