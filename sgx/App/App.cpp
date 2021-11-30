/*
 * Created on Fri Jul 17 2020
 *
 * Copyright (c) 2020 Peterson Yuhala, IIUN
 */

/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <sys/time.h>
#define MAX_PATH FILENAME_MAX

#include <sys/types.h>
#include <sys/socket.h>

#include "graalsgx/net/graal_net.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/sysinfo.h>
#include <cassert>
#define assertm(exp, msg) assert(((void)msg, exp))

//#define ____sigset_t_defined
#define __iovec_defined 1

#include "Enclave_u.h"
#include "sgx_urts.h"

#include <sgx_spinlock.h>

#include "App.h"
#include "error/error.h"

// Graal headers
#include "graal_isolate.h"
#include "main.h"
#include "user_types.h"

// switchless headers
#include "switchless_buffer.h"
#include <sched.h>
#include <sys/syscall.h>

/* Signal handlers */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <map>
#include "ocall_logger.h"

#include "graal_sgx_shim_switchless_u.h"

//paldb benchmarking
#include "polydb/Polydb.h"

//zc switchless
#include "zcUntrusted/zc_out.h"

//intel sdk switchless lib
#include <sgx_uswitchless.h>

//for get_nprocs()
#include <sys/sysinfo.h>

#include "zc_types.h"

/* Benchmarking */
#include "bench/benchtools.h"
#include "bench/cpu_usage.h"
#include <time.h>
struct timespec start, stop;
double diff;
using namespace std;
extern std::map<pthread_t, pthread_attr_t *> attr_map;

/**
 * globals for getting cpu stats
 */
unsigned long long **cpu_stats_begin;
unsigned long long **cpu_stats_end;

extern unsigned long int total_sl; /* total # of switchless calls at runtime */
extern unsigned long int total_fb; /* total # of fallback calls at runtime */

extern pthread_mutex_t ocall_counter_lock;

/* Macro for this value which is in the config file of the enclave because I
 * don't know how to do better
 */
// pyuhala: these should be fixed b/c they are machine dependent; try using
// global variables instead, which you can set to the right values at the start of the program
// for example: num of cores can be obtained with get_nprocs()

#define SGX_TCS_NUM 8
#define CORES_NUM 4
#define TIME_ENCLAVE_SWITCH 13500
#define TIME_MICRO_QUANTUM 100000 // 1000000 = 1ms
#define MICRO_INVERSE 100
#define CPU_FREQ 3.8

extern bool use_zc_scheduler;

/* arguments of the worker threads */
struct worker_args
{
    struct buffer *buffer;
    int worker_id;
};

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
/* Corresponding global buffers */
struct buffer switchless_buffers[CORES_NUM / 2];
/* runtime stats */
volatile sig_atomic_t number_of_sl_calls = 0;
volatile sig_atomic_t number_of_fallbacked_calls = 0;
volatile sig_atomic_t number_of_workers = 0;
//int number_of_useful_schedulings = 0;
//pthread_t workers[CORES_NUM / 2];

/* Main app isolate */
graal_isolatethread_t *global_app_iso;
/*Main thread id*/
//std::thread::id main_thread_id = std::this_thread::get_id();
pthread_t main_thread_id;

/* Ocall counter */
extern std::map<std::string, int> ocall_map;
extern unsigned int ocall_count;

//pyuhala: for intel sdk switchless calls
//#define SL_DEFAULT_FALLBACK_RETRIES 20000

bool use_zc_switchless = false;

extern unsigned int num_workers;
extern zc_stats *zc_statistics;

//pyuhala: forward declarations
void run_kissdb_bench(int num_runs);
void runTestMulti(int num_runs);
void run_zc_micro(int num_runs);
void run_kyoto_bench();
void remove_kc_dbs();
void run_kyoto_bench(int numRuns);

void gen_sighandler(int sig, siginfo_t *si, void *arg)
{
    printf("Caught signal: %d\n", sig);
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

void fill_array()
{
    printf("Filling outside array\n");
    unsigned int size = 1024 * 1024 * 4; //16mb
    int *array = (int *)malloc(sizeof(int) * size);
    int idx = 0;
    for (int i = 0; i < size; i++)
    {
        array[i] = i;
        idx = i;
    }
    printf("Largest index is %d\n", idx);
}

int getCpus()
{
    int ret = get_nprocs();
    printf("Number of cores: %d\n", ret);
    return ret;
}

/**
 * Set main thread attribs
 */
void setMainAttribs()
{
    main_thread_id = pthread_self();
    pthread_attr_t *attr = (pthread_attr_t *)malloc(sizeof(pthread_attr_t));
    int ret = pthread_getattr_np(main_thread_id, attr);
    attr_map.insert(pair<pthread_t, pthread_attr_t *>(main_thread_id, attr));
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave_no_switchless(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(const sgx_uswitchless_config_t *us_config)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    const void *enclave_ex_p[32] = {0};

    enclave_ex_p[SGX_CREATE_ENCLAVE_EX_SWITCHLESS_BIT_IDX] = (const void *)us_config;

    ret = sgx_create_enclave_ex(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL, SGX_CREATE_ENCLAVE_EX_SWITCHLESS, enclave_ex_p);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* Code of a benchmarking thread */
void *enclave_bench_thread(void *arg)
{
    size_t i = *((size_t *)arg);
    //ecall_bench_thread(global_eid, switchless_buffers, &switchless_buffers[i % (CORES_NUM / 2)], shim_switchless_functions, shim_functions, (int *)&number_of_sl_calls, (int *)&number_of_fallbacked_calls, (int *)&number_of_workers);
    return NULL;
}

/* Code of gettid for an enclave thread */
long ocall_gettid(void)
{
    pid_t ret;
    ret = syscall(SYS_gettid);
    return ret;
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

/**
 * Initialize and launch enclave w/o all the switchless stuff
 * Pyuhala
 */

int normal_run(int arg)
{

    setMainAttribs();

    attr_map.insert(pair<pthread_t, pthread_attr_t *>(0, NULL));
    /* Initialize the enclave */

    if (initialize_enclave_no_switchless() < 0)
    {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }
    printf("Enclave initialized\n");

    int id = global_eid;
    ecall_run_main(global_eid, id);

    printf("Number of ocalls: %d\n", ocall_count);
    showOcallLog(50);

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    return 0;
}

//pthread_t scheduling_thread;

/* Initializing the buffers */
void init_switchless(void)
{
    //removed due to linkage issues
}

void destroy_switchless(void)
{
}

void removeKissDbs()
{
    //printf(">>>>>>>>>>>>>>..removing kissdb files..>>>>>>>>>>>>>>>>>\n");
    int ret = system("rm kissdb*");
    ZC_ASSERT(!ret);
}

/**
 * remove all kyoto cabinet dbs
 */
void remove_kc_dbs()
{
    //printf(">>>>>>>>>>>>>>..removing kissdb files..>>>>>>>>>>>>>>>>>\n");
    int ret = system("rm *.kcd");
    ZC_ASSERT(!ret);
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
            //printf("<--------------------- running test multi ----------------------->\n", i);
            start_clock();
            write_keys(i, numThreads);
            //read_keys(i, numReaders);
            stop_clock();
            total_runtime += time_diff(&start, &stop, SEC);
        }
        avg_runtime = total_runtime / num_runs;

        register_results(path, i, avg_runtime);
        printf(">>>>>>>>>>>>>>>>> test multi %d: COMPLETE >>>>>>>>>>>>>>>>>\n", i);
    }
    printf(">>>>>>>>>>>>>>>>> test multi bench END >>>>>>>>>>>>>>>>>\n");
}

void run_kissdb_bench(int numRuns)
{

    //most frequent ocalls
    /* Ocall: ocall_fseeko Count: 2399250
Ocall: ocall_fwrite Count: 1577020
Ocall: ocall_fread Count: 1349250 */

    printf(">>>>>>>>>>>>>>>>> kissdb bench START >>>>>>>>>>>>>>>>>\n");
    int minKeys = 500;
    int maxKeys = 10000;
    int step = 500;
    int numWriters = 2;
    int numReaders = 2;
    //write_keys(numKeys, numWriters);
    //bool test = (numReaders == numWriters);

    char path[20];
    snprintf(path, 20, "results_kissdb.csv");

    //ZC_ASSERT(test);

    double totalRuntime;
    double avgRuntime;
    double tput;
    double cpu_usage;
    double avg_cpu;

    for (int i = minKeys; i <= maxKeys; i += step)
    {

        totalRuntime = 0;
        avgRuntime = 0;
        cpu_usage = 0;

        for (int j = 0; j < numRuns; j++)
        {

            start_clock();

            cpu_stats_begin = read_cpu();
            write_keys(i, numWriters);
            cpu_stats_end = read_cpu();

            stop_clock();
            totalRuntime += time_diff(&start, &stop, SEC);
            cpu_usage += get_avg_cpu_usage(cpu_stats_end, cpu_stats_begin);

            free(cpu_stats_begin);
            free(cpu_stats_end);
            removeKissDbs();
        }

        avgRuntime = totalRuntime / numRuns;
        tput = i / avgRuntime; // ops/sec
        avg_cpu = cpu_usage / numRuns;

        //register_results(path, i, avgRuntime, tput);
        register_results(path, i, 0, avg_cpu);

        printf(">>>>>>>>>>>>>>>>> kissdb bench: PUT %d keys COMPLETE >>>>>>>>>>>>>>>>>\n", i);
    }
    printf(">>>>>>>>>>>>>>>>> kissdb bench END >>>>>>>>>>>>>>>>>\n");
}

void run_kyoto_bench(int numRuns)
{

    char path[20];
    snprintf(path, 20, "results_kyoto.csv");

    printf(">>>>>>>>>>>>>>>>> kyoto bench START >>>>>>>>>>>>>>>>>\n");
    int minKeys = 500;
    int maxKeys = 10000;
    int step = 500;
    int numWriters = 2;

    double totalRuntime;
    double avgRuntime;
    double tput;
    double cpu_usage;
    double avg_cpu;

    for (int i = minKeys; i <= maxKeys; i += step)
    {

        totalRuntime = 0;
        avgRuntime = 0;
        cpu_usage = 0;
        for (int j = 0; j < numRuns; j++)
        {
            start_clock();

            cpu_stats_begin = read_cpu();
            write_keys(i, numWriters);
            cpu_stats_end = read_cpu();

            stop_clock();
            totalRuntime += time_diff(&start, &stop, SEC);
            cpu_usage += get_avg_cpu_usage(cpu_stats_end, cpu_stats_begin);

            free(cpu_stats_begin);
            free(cpu_stats_end);
            remove_kc_dbs();
        }
        avgRuntime = totalRuntime / numRuns;
        tput = i / avgRuntime; // ops/sec
        avg_cpu = cpu_usage / numRuns;

        register_results(path, i, avgRuntime, avg_cpu);
        printf(">>>>>>>>>>>>>>>>> kyoto bench: SET %d keys COMPLETE >>>>>>>>>>>>>>>>>\n", i);
    }
    printf(">>>>>>>>>>>>>>>>> kyoto bench END >>>>>>>>>>>>>>>>>\n");
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
    //write_keys(numKeys, numWriters);
    //bool test = (numReaders == numWriters);

    char path[20];
    snprintf(path, 20, "zc_micro_results.csv");

    //ZC_ASSERT(test);

    double total_runtime;
    double avg_runtime;

    for (int i = min_keys; i <= max_keys; i += step)
    {

        total_runtime = 0;
        avg_runtime = 0;
        for (int j = 0; j < num_runs; j++)
        {
            //printf("<--------------------- running test multi ----------------------->\n", i);
            start_clock();
            write_keys(i, numWriters);
            //read_keys(i, numReaders);
            stop_clock();
            total_runtime += time_diff(&start, &stop, SEC);
            remove_zc_files();
        }
        avg_runtime = total_runtime / num_runs;

        register_results(path, i, avg_runtime);
        printf(">>>>>>>>>>>>>>>>> zc micro bench: writing %d lines COMPLETE >>>>>>>>>>>>>>>>>\n", i);
    }
    printf(">>>>>>>>>>>>>>>>> zc micro bench END >>>>>>>>>>>>>>>>>\n");
}

/* Application entry */
int main(int argc, char *argv[])
{

    //print_stack_protector_checks();

    (void)(argc);
    (void)(argv);

    int i;
    struct timeval tval_before, tval_after, tval_result;

    int num_mcd_workers = 2;
    int sdk_switchless = 0;
    int zc_switchless = 0;
    int ret_zero = 1;

    use_zc_scheduler = true;

    // number of switchless worker threads
    int num_sl_workers = get_nprocs() / 2;

    if (argc == 3)
    {

        zc_switchless = atoi(argv[1]);
        sdk_switchless = atoi(argv[2]);
    }

    //int ret = normal_run(arg1);
    //return ret;

    setMainAttribs();
    pthread_mutex_init(&ocall_counter_lock, NULL);

    attr_map.insert(pair<pthread_t, pthread_attr_t *>(0, NULL));

    /**
     * Intel SDK switchless configuration
     */

    sgx_uswitchless_config_t us_config = SGX_USWITCHLESS_CONFIG_INITIALIZER;

    if (zc_switchless && sdk_switchless)
    {
        printf("xxxxxxxxxxxxxxx cannot activate both SDK and ZC switchless at the same time xxxxxxxxxxxxxxxxxx\n");
        printf("usage: ./memcached-sgx [zc_switchless] [sdk_switchless]\n");
        return 0;
    }

    /* Initialize the enclave */

    if (!sdk_switchless)
    {
        //do not use switchless
        if (initialize_enclave_no_switchless() < 0)
        {
            printf("Enter a character before exit ...\n");
            getchar();
            return -1;
        }
    }
    else
    {
        //use intel sdk switchless
        printf("########################## running in INTEL-SDK-SWITCHLESS mode ##########################");
        us_config.num_uworkers = num_sl_workers;
        //pyuhala: we are not concerned with switchless ecalls so no trusted workers
        us_config.num_tworkers = 0;
        if (initialize_enclave(&us_config) < 0)
        {
            printf("Enter a character before exit ...\n");
            getchar();
            return -1;
        }
    }

    // stack protector checks in enclave
    //ecall_undef_stack_protector(global_eid);

    /**
     * ZC-switchless initialization
     */

    if (zc_switchless)
    {
        printf("########################## running in ZC-SWITCHLESS mode ##########################\n");
        ret_zero = 0;
        //init_switchless();
        init_zc(num_sl_workers);

        //return 0;
    }

    // ecall_test(global_eid);
    // return 0;

    printf("Enclave initialized\n");

    int id = global_eid;

    //init_memcached(num_mcd_workers);
    //run_kissdb_bench(5);
    //run_zc_micro(1);
    run_kyoto_bench(5);

    //return 0;

    //ecall_create_enclave_isolate(global_eid);
    /**
     * Read/Write n kv pairs in paldb with m threads
     * PYuhala
     */

    //ecall_kissdb_test(global_eid);

    //runTestMulti(10);

    if (zc_switchless)
    {
        unsigned long int sl, fb;
        if (use_zc_scheduler)
        {
            /**
             * The scheduler reinitializes zc_stats, 
             * but tracks the totals in these variables.
             */
            sl = total_sl;
            fb = total_fb;
        }
        else
        {
            /**
             * We didn't use scheduler so these values are 
             * valid
             */
            sl = zc_statistics->num_zc_swtless_calls;
            fb = zc_statistics->num_zc_fallback_calls;
        }

        printf("<<<< COMPLETE ZC SWITCHLESS CALLS: %ld ZC FALLBACK CALLS: %ld >>>>\n", sl, fb);
        showOcallLog(5);
        printf("Total OCALLS (switchless + not) = %d\n", ocall_count);
    }
    else
    {
        showOcallLog(5);
    }

    //finalize_zc();
    return 0;

    /**
     * pyuhala: this prevents read errors in kissdb (eg readers reading from a non-existent file).
     *  Still to fix the issue
     */
    //assertm(test, "num of reader threads should be = num of writer threads or have only 1 writer thread ");
    //read_keys(numKeys, numReaders);

    //ecall_kissdb_test(global_eid);

    showOcallLog(10);

    return 0;

    if (zc_switchless)
    {
        destroy_switchless();
    }

    printf("Number of ocalls: %d\n", ocall_count);
    showOcallLog(10);

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    return 0;
}
