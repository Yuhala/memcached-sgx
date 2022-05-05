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

#include "headers.h"
#include "App.h"
#include "bench/bench.h"

// for benchmarking
#include "polydb/polydb.h"

#define MAX_PATH FILENAME_MAX
using namespace std;
extern std::map<pthread_t, pthread_attr_t *> attr_map;

extern unsigned long int total_sl; /* total # of switchless calls at runtime */
extern unsigned long int total_fb; /* total # of fallback calls at runtime */

extern pthread_mutex_t ocall_counter_lock;

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
// int number_of_useful_schedulings = 0;
// pthread_t workers[CORES_NUM / 2];

/* Main app isolate */
graal_isolatethread_t *global_app_iso;
/*Main thread id*/
// std::thread::id main_thread_id = std::this_thread::get_id();
pthread_t main_thread_id;

/* Ocall counter */
extern std::map<std::string, int> ocall_map;
extern unsigned int ocall_count;

// pyuhala: for intel sdk switchless calls
//#define SL_DEFAULT_FALLBACK_RETRIES 20000

bool use_zc_switchless = false;

extern unsigned int num_workers;
extern zc_stats *zc_statistics;

extern unsigned int num_active_zc_workers;

/**
 * flags specifying which system to use
 */
int sdk_switchless = 0;
int zc_switchless = 0;

/**
 * get the number of active (not sleeping) workers
 * for the switchless system being used.
 */
unsigned int get_num_active_workers()
{
    if (sdk_switchless)
    {
        return 2;
    }
    else if (zc_switchless)
    {
        return num_active_zc_workers;
    }
    else
    {
        return 0;
    }
}

void gen_sighandler(int sig, siginfo_t *si, void *arg)
{
    printf("Caught signal: %d\n", sig);
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
void set_main_attribs()
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

/* Code of gettid for an enclave thread */
long ocall_gettid(void)
{
    pid_t ret;
    ret = syscall(SYS_gettid);
    return ret;
}

/**
 * Initialize and launch enclave w/o all the switchless stuff
 * Pyuhala
 */

int normal_run(int arg)
{

    set_main_attribs();

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
    show_ocall_log(50);

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    return 0;
}

/* Application entry */
int main(int argc, char *argv[])
{

    // print_stack_protector_checks();

    (void)(argc);
    (void)(argv);

    int i;
    struct timeval tval_before, tval_after, tval_result;

    int num_mcd_workers = 2;

    int ret_zero = 1;

    use_zc_scheduler = true;

    // number of switchless worker threads
    int num_sl_workers = 2;//get_nprocs() / 2;

    /**
     * use zc: ./async-sgx 1 0
     * use intel: ./async-sgx 0 1
     */
    if (argc == 3)
    {

        zc_switchless = atoi(argv[1]);
        sdk_switchless = atoi(argv[2]);
    }

    // int ret = normal_run(arg1);
    // return ret;

    set_main_attribs();
    pthread_mutex_init(&ocall_counter_lock, NULL);

    attr_map.insert(pair<pthread_t, pthread_attr_t *>(0, NULL));

    /**
     * Intel SDK switchless configuration
     */

    sgx_uswitchless_config_t us_config = SGX_USWITCHLESS_CONFIG_INITIALIZER;

    if (zc_switchless && sdk_switchless)
    {
        printf("xxxxxxxxxxxxxxx cannot activate both SDK and ZC switchless at the same time xxxxxxxxxxxxxxxxxx\n");
        printf("usage: ./async-sgx [zc_switchless] [sdk_switchless]\n");
        return 0;
    }

    /* Initialize the enclave */

    if (sdk_switchless == 0)
    {
        // do not use switchless
        if (initialize_enclave_no_switchless() < 0)
        {
            printf("Enter a character before exit ...\n");
            getchar();
            return -1;
        }
    }
    else if (sdk_switchless == 1)
    {
        // use intel sdk switchless
        printf("########################## running in INTEL-SDK-SWITCHLESS mode. #workers: %d ##########################\n", num_sl_workers);
        us_config.num_uworkers = num_sl_workers;
        // pyuhala: we are not concerned with switchless ecalls so no trusted workers
        us_config.num_tworkers = 0;
        /**
         * define the number of retries before fallback.
         */
        //us_config.retries_before_fallback = 0;

        if (initialize_enclave(&us_config) < 0)
        {
            printf("Enter a character before exit ...\n");
            getchar();
            return -1;
        }
    }

    // stack protector checks in enclave
    // ecall_undef_stack_protector(global_eid);

    /**
     * ZC-switchless initialization
     */

    if (zc_switchless)
    {
        printf("########################## running in ZC-SWITCHLESS mode. # workers: %d ##########################\n", num_sl_workers);
        ret_zero = 0;
        // init_switchless();
        init_zc(num_sl_workers);

        // return 0;
    }

    // ecall_test(global_eid);
    // return 0;

    printf("Enclave initialized\n");

    int id = global_eid;
    double run_time = 60.0;

    //-------------------------------------------
    run_bench_dynamic(run_time, 1);

    //run_lmbench(3);

    //run_kissdb_bench(2);

    //-------------------------------------------

    // init_memcached(num_mcd_workers);
    // run_zc_micro(1);
    // run_kyoto_bench(5);

    // run_zc_fg(5);

    // return 0;

    // ecall_create_enclave_isolate(global_eid);
    /**
     * Read/Write n kv pairs in paldb with m threads
     * PYuhala
     */

    // ecall_kissdb_test(global_eid);

    // runTestMulti(10);

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
        show_ocall_log(5);
        printf("Total OCALLS (switchless + not) = %d\n", ocall_count);
    }
    else
    {
        show_ocall_log(5);
    }

    // finalize_zc();
    return 0;

    /**
     * pyuhala: this prevents read errors in kissdb (eg readers reading from a non-existent file).
     *  Still to fix the issue
     */
    // assertm(test, "num of reader threads should be = num of writer threads or have only 1 writer thread ");
    // read_keys(numKeys, numReaders);

    // ecall_kissdb_test(global_eid);

    show_ocall_log(10);

    return 0;

    if (zc_switchless)
    {
        destroy_switchless();
    }

    printf("Number of ocalls: %d\n", ocall_count);
    show_ocall_log(10);

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    return 0;
}
