/*
 * Created on Thu Apr 21 2022
 *
 * Copyright (c) 2022 Peterson Yuhala
 */

#include "headers.h"

// for benchmarking
#include "polydb/polydb.h"

static struct timespec start, stop;
static double diff;

/**
 * globals for getting cpu stats
 */
static unsigned long long **cpu_stats_begin;
static unsigned long long **cpu_stats_end;

/* Code of a benchmarking thread */
void *enclave_bench_thread(void *arg)
{
    size_t i = *((size_t *)arg);
    // ecall_bench_thread(global_eid, switchless_buffers, &switchless_buffers[i % (CORES_NUM / 2)], shim_switchless_functions, shim_functions, (int *)&number_of_sl_calls, (int *)&number_of_fallbacked_calls, (int *)&number_of_workers);
    return NULL;
}

/* Code of the benchmark */
void ocall_bench(void)
{
    size_t i;
    pthread_t threads[SGX_TCS_NUM];
    size_t args[SGX_TCS_NUM];
    struct sched_param param;

    /* setting the thread's priority to a high priority */
    /*param.sched_priority = 1;
    if (sched_setscheduler(0, SCHED_RR, &param) == -1)
    {
    perror("Unable to change the policy of a worker thread to SCHED_RR");
    exit(1);
    }*/

    for (i = 0; i < SGX_TCS_NUM; i++)
        args[i] = i;
    for (i = 0; i < SGX_TCS_NUM; i++)
        if (pthread_create(&threads[i], NULL, enclave_bench_thread, &args[i]) != 0)
        {
            fprintf(stderr, "Error creating bench thread number %d, exiting\n", i);
            exit(1);
        }
    for (i = 0; i < SGX_TCS_NUM; i++)
        if (pthread_join(threads[i], NULL) != 0)
        {
            fprintf(stderr, "Error joining bench thread number %d, exiting\n", i);
            exit(1);
        }
}

void remove_zc_files()
{
    int ret = system("rm zcstore*");
    ZC_ASSERT(!ret);
}

void runTestMulti(int num_runs)
{

    char path[20];
    snprintf(path, 20, "testmulti_results.csv");

    int min = 5000;
    int max = 80000;
    int step = 5000;

    double total_runtime;
    double avg_runtime;

    int numThreads = 2;

    for (int i = min; i <= max; i += step)
    {
        total_runtime = 0;
        avg_runtime = 0;
        for (int j = 0; j < num_runs; j++)
        {
            // printf("<--------------------- running test multi ----------------------->\n", i);
            start_clock(&start);
            write_keys(i, numThreads);
            // read_keys(i, numReaders);
            stop_clock(&stop);
            total_runtime += time_diff(&start, &stop, SEC);
        }
        avg_runtime = total_runtime / num_runs;

        register_results(path, i, avg_runtime);
        printf(">>>>>>>>>>>>>>>>> test multi %d: COMPLETE >>>>>>>>>>>>>>>>>\n", i);
    }
    printf(">>>>>>>>>>>>>>>>> test multi bench END >>>>>>>>>>>>>>>>>\n");
}

void run_zc_fg(int numRuns)
{

    int fpercent = 10;
    char path[20];
    snprintf(path, 20, "results_zc_fg.csv");

    printf(">>>>>>>>>>>>>>>>> zc fg bench START >>>>>>>>>>>>>>>>>\n");
    int min = 5000;
    int max = 100000;
    int step = 5000;
    int numWriters = 2;

    double totalRuntime;
    double avgRuntime;
    double cpu_usage;
    double avg_cpu;

    for (int i = min; i <= max; i += step)
    {

        totalRuntime = 0;
        avgRuntime = 0;
        cpu_usage = 0;
        for (int j = 0; j < numRuns; j++)
        {
            start_clock(&start);

            cpu_stats_begin = read_cpu();
            write_keys(i, numWriters);
            cpu_stats_end = read_cpu();

            stop_clock(&stop);
            totalRuntime += time_diff(&start, &stop, SEC);
            cpu_usage += get_avg_cpu_usage(cpu_stats_end, cpu_stats_begin);

            free(cpu_stats_begin);
            free(cpu_stats_end);
        }
        avgRuntime = totalRuntime / numRuns;

        avg_cpu = cpu_usage / numRuns;

        register_results(path, i, avgRuntime, avg_cpu);
        printf(">>>>>>>>>>>>>>>>> zc fg bench: total calls: %d COMPLETE >>>>>>>>>>>>>>>>>\n", i);
    }
    printf(">>>>>>>>>>>>>>>>> zc fg bench END >>>>>>>>>>>>>>>>>\n");
}

/**
 * micro benchmark that writes and reads text to file from within enclave
 */
void run_zc_micro(int num_runs)
{
    printf(">>>>>>>>>>>>>>>>> zc micro-bench START >>>>>>>>>>>>>>>>>\n");
    int min_keys = 10;
    int max_keys = 10;
    int step = 10;
    int numWriters = 2;
    int numReaders = 2;
    // write_keys(numKeys, numWriters);
    // bool test = (numReaders == numWriters);

    char path[20];
    snprintf(path, 20, "zc_micro_results.csv");

    // ZC_ASSERT(test);

    double total_runtime;
    double avg_runtime;

    for (int i = min_keys; i <= max_keys; i += step)
    {

        total_runtime = 0;
        avg_runtime = 0;
        for (int j = 0; j < num_runs; j++)
        {
            // printf("<--------------------- running test multi ----------------------->\n", i);
            start_clock(&start);
            write_keys(i, numWriters);
            // read_keys(i, numReaders);
            stop_clock(&stop);
            total_runtime += time_diff(&start, &stop, SEC);
            remove_zc_files();
        }
        avg_runtime = total_runtime / num_runs;

        register_results(path, i, avg_runtime);
        printf(">>>>>>>>>>>>>>>>> zc micro bench: writing %d lines COMPLETE >>>>>>>>>>>>>>>>>\n", i);
    }
    printf(">>>>>>>>>>>>>>>>> zc micro bench END >>>>>>>>>>>>>>>>>\n");
}

void fill_array()
{
    printf("Filling outside array\n");
    unsigned int size = 1024 * 1024 * 4; // 16mb
    int *array = (int *)malloc(sizeof(int) * size);
    int idx = 0;
    for (int i = 0; i < size; i++)
    {
        array[i] = i;
        idx = i;
    }
    printf("Largest index is %d\n", idx);
}

/**
 * check for definitions of some stack protector macros
 */
void print_stack_protector_checks()
{
#ifdef __SSP__
    printf("__SSP macro is defined, with value 1, -fstack-protector is in use.\n");
#endif

#ifdef __SSP_ALL__
    printf("__SSP_ALL__ macro is defined, with value 2, -fstack-protector-all is in use.\n");
#endif

#ifdef __SSP_STRONG__
    printf("__SSP_STRONG__ macro is defined, with value 3, -fstack-protector-strong is in use.\n");
#undef __SSP_STRONG__
#endif

#ifdef __SSP_EXPLICIT__
    printf("__SSP_EXPLICIT__ macro is defined, with value 4, -fstack-protector-explicit is in use.\n");
#endif
}

// pthread_t scheduling_thread;

/* Initializing the buffers */
void init_switchless(void)
{
    // removed due to linkage issues
}

void destroy_switchless(void)
{
}
