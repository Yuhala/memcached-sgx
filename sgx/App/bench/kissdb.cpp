/*
 * Created on Thu Apr 21 2022
 *
 * Copyright (c) 2022 Peterson Yuhala
 */

#include "headers.h"

// paldb benchmarking
#include "polydb/polydb.h"

static struct timespec start, stop;
static double diff;

/**
 * globals for getting cpu stats
 */
static unsigned long long **cpu_stats_begin;
static unsigned long long **cpu_stats_end;

void remove_old_dbs()
{
    // printf(">>>>>>>>>>>>>>..removing kissdb files..>>>>>>>>>>>>>>>>>\n");
    int ret = system("rm kissdb* lmbench*");
    //ZC_ASSERT(!ret);
}

void remove_old_results()
{
    int ret = system("rm results_kissdb* results_lmbench*");
    //ZC_ASSERT(!ret);
}

void run_kissdb_bench(int numRuns)
{

    // most frequent ocalls
    /* Ocall: ocall_fseeko Count: 2399250
    Ocall: ocall_fwrite Count: 1577020
    Ocall: ocall_fread Count: 1349250 */

    printf(">>>>>>>>>>>>>>>>> kissdb bench START >>>>>>>>>>>>>>>>>\n");
    int min_keys = 500;
    int max_keys = 10000;
    int step = 500;
    int num_writers = 2;
    int num_readers = 2;
    // write_keys(numKeys, num_writers);
    // bool test = (num_readers == num_writers);

    char path[20];
    snprintf(path, 20, "results_kissdb.csv");

    // ZC_ASSERT(test);

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

        for (int j = 0; j < numRuns; j++)
        {

            start_clock(&start);

            cpu_stats_begin = read_cpu();
            write_bench(i, num_writers);
            cpu_stats_end = read_cpu();

            stop_clock(&stop);
            total_runtime += time_diff(&start, &stop, SEC);
            cpu_usage += get_avg_cpu_usage(cpu_stats_end, cpu_stats_begin);

            free(cpu_stats_begin);
            free(cpu_stats_end);
            remove_old_dbs();
        }

        avg_runtime = total_runtime / numRuns;
        tput = i / avg_runtime; // ops/sec
        avg_cpu = cpu_usage / numRuns;

        // register_results(path, i, avg_runtime, tput);
        register_results(path, i, avg_runtime, tput, avg_cpu);

        printf(">>>>>>>>>>>>>>>>> kissdb bench: PUT %d keys COMPLETE >>>>>>>>>>>>>>>>>\n", i);
    }
    printf(">>>>>>>>>>>>>>>>> kissdb bench END >>>>>>>>>>>>>>>>>\n");
}

/**
 * Peterson Yuhala
 * This goal of this bench is to have enclave callers issuing a more or less dynamic workload.
 * We vary the request frequency of the callers. We do this by "playing with sleep time" between requests.
 * The total runtime input will be divided into 3 stages: in the first stage we increase request frequency,
 * in the second stage we keep it constant at a certain max value, and in the third stage we decrease the request frequency
 * until the total time expires, where the benchmark is stopped.
 *
 * The metrics we aim to study at different timestamps are:
 * request throughput = (num OPs/time taken);
 * number of running worker threads at a timestamp t;
 * CPU % at a timestamp t;
 *
 * The sleeping logic is done in the writer_thread routine in Polydb.cpp
 *
 */
void run_bench_dynamic(double run_time, int num_runs)
{
    // most frequent ocalls
    /* Ocall: ocall_fseeko Count: 2399250
    Ocall: ocall_fwrite Count: 1577020
    Ocall: ocall_fread Count: 1349250 */

    remove_old_dbs(); // clean old files
    remove_old_results();
    
    printf(">>>>>>>>>>>>>>>>> kissdb dynamic bench start >>>>>>>>>>>>>>>>>\n");

    int num_req = 2000; // number of requests issued by the callers

    int min_keys = 500;
    int max_keys = 10000;
    int step = 500;    
    int num_threads = 2;;

    bench_dynamic(num_req, num_threads, run_time);

    // char path[30];
    // snprintf(path, 30, "results_kissdb_dynamic.csv");

    // ZC_ASSERT(test);

    double total_runtime;
    double avg_runtime;
    double tput;
    double cpu_usage;
    double avg_cpu;
}