
/*
 * Created on Fri Aug 27 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#include "polydb.h"
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "bench/benchtools.h"
#include "bench/cpu_usage.h"

#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>

#include "zc_types.h"

#include <fcntl.h>

extern sgx_enclave_id_t global_eid;
extern struct buffer switchless_buffers[];
extern __thread struct buffer *switchless_buffer;
extern volatile sig_atomic_t number_of_sl_calls;
extern volatile sig_atomic_t number_of_fallbacked_calls;
extern volatile sig_atomic_t number_of_workers;
extern void *shim_switchless_functions[];
extern void *shim_functions[];

extern bool use_zc_switchless;

extern unsigned int num_active_zc_workers;

/**
 * specifies if caller threads
 * should start their work or not
 */
volatile int start = 0;

/**
 * number of seconds for the min request frequency
 * i.e numReq will be issued every maxSleep for the lowest frequency
 * I chose 1s here because it corresponds to the max usleep time i.e 1000 000 in useconds_t
 */
static double max_sleep = 1.0;
/**
 * number of secs for the min request frequency
 * todo: find a better value
 */
static double min_sleep = 0.03125;

/**
 * register start time for the writer threads.
 * this is done by the main thread
 */
static struct timespec bench_start_time;

/**
 * time spent since atleast one of the caller threads began sending requests
 */

static double time_spent = 0.0;
/**
 * Used by the writers. We need to make sure any 2 writers don't use the same
 * storeId ==> storeFile
 */
static int write_store_counter = 0;
static int read_store_counter = 0;
pthread_mutex_t kissdb_lock;

pthread_mutex_t bench_timer_lock;

struct thread_args
{
    int num_keys;
    /*read/writer id*/
    int rw_id;
    /*bench time in secs*/
    double run_time;
    /* operation type*/
    op_type operation;
    /* fd and file path*/
    _state *file_info;
};

/**
 * flags specifying which system to use
 */
extern int sdk_switchless;
extern int zc_switchless;

/**
 * lmbench reads from /dev/zero
 */
_state *get_read_cookie()
{

    _state *cookie = (_state *)malloc(sizeof(_state));
    cookie->fd = open("/dev/zero", O_RDONLY);
    cookie->file = NULL; // we already know it will be /dev/zero

    return cookie;
}

/**
 * lmbench writes to /dev/null
 */
_state *get_write_cookie()
{

    _state *cookie = (_state *)malloc(sizeof(_state));
    cookie->fd = open("/dev/null", O_WRONLY);
    cookie->file = NULL; // we already know it will be /dev/zero

    return cookie;
}

/**
 * pyuhala:
 * reader/writer threads should wait
 * for the main thread to finish creating all threads
 * and set the start flag before they begin reading/writing.
 * This minimizes the lag between the spawned threads.
 */

void wait_for_start()
{
    /**
     * busy wait loop
     */
    while (__atomic_load_n(&start, __ATOMIC_RELAXED) != 1)
    {
        ZC_PAUSE();
    }
}

void *reader_thread(void *input)
{
    int n = ((struct thread_args *)input)->num_keys;
    // int id = ((struct thread_args *)input)->rw_id;
    // readers read in the store corresponding to their store id

    // int id = (write_store_counter > 0) ? write_store_counter - 1 : 0;
    int id = __atomic_fetch_add(&read_store_counter, 1, __ATOMIC_RELAXED);

    ecall_read_kissdb(global_eid, n, id);
}

/**
 * writer thread routine for static workload
 */
void *writer_thread(void *input)
{

    int n = ((struct thread_args *)input)->num_keys;
    // int id = ((struct thread_args *)input)->rw_id;

    // pthread_mutex_lock(&lock);
    // id = write_store_counter++;
    int id = __atomic_fetch_add(&write_store_counter, 1, __ATOMIC_RELAXED);
    // pthread_mutex_unlock(&lock);

    // ecall_write_kyotodb(global_eid, n, id);
    ecall_write_kissdb(global_eid, n, id);
    // ecall_run_fg(global_eid, n, id);
}

/**
 * writer thread routine for dynamic workload
 */
void *thread_dynamic(void *input)
{

    wait_for_start();
    // pthread_mutex_lock(&lock);
    // id = write_store_counter++;
    int id = __atomic_fetch_add(&write_store_counter, 1, __ATOMIC_RELAXED);
    // pthread_mutex_unlock(&lock);

    int num_req = ((struct thread_args *)input)->num_keys;
    int operation = ((struct thread_args *)input)->operation;
    void *cookie = (void *)((struct thread_args *)input)->file_info;

    // probably not the cleanest practice
    unsigned int sleep_micro = static_cast<unsigned int>(max_sleep * MICRO_SECS);

    // workload status: we start at increasing workload
    workload_state state = INCREASE;

    double run_time = ((struct thread_args *)input)->run_time;

    // time thread spends in each state
    double state_slot_time = run_time / NUM_STATES;

    // create results file
    char *res_file = create_results_file(id);

    /**
     * cpu usage stats
     */
    unsigned long long **cpu_stats_begin;
    unsigned long long **cpu_stats_end;
    double cpu_usage = 0.0;

    while (time_spent < run_time)
    {

        /**
         * this code snippet only makes sense with the current 3 state design
         */
        bool test_inc = (time_spent < state_slot_time);
        bool test_const = (time_spent >= state_slot_time) && (time_spent < 2 * state_slot_time);

        if (test_inc)
        {
            state = INCREASE;
        }
        else if (test_const)
        {
            state = CONSTANT;
        }
        else
        {
            state = DECREASE;
        }

        /**
         * request times for different states
         */
        double req_time_inc;
        double req_time_const;
        double req_time_dec;

        switch (state)
        {
        case INCREASE:
            //printf(">>> INCREASING FREQUENCY >>>\n");
            /**
             * Send num_req write requests to the enclave.
             * We could calculate time spent out of the switch
             * block, but I think it makes sense to have it just after
             * performing the requests in each case,
             *  and computing cpu usage during the request period.
             */

            cpu_stats_begin = read_cpu();
            req_time_inc = do_request(num_req, id, operation, cookie);
            cpu_stats_end = read_cpu();

            pthread_mutex_lock(&bench_timer_lock);
            time_spent = elapsed_time(&bench_start_time);
            pthread_mutex_unlock(&bench_timer_lock);

            cpu_usage = get_avg_cpu_usage(cpu_stats_end, cpu_stats_begin);
            register_results_dynamic(res_file, time_spent, get_tput(num_req, req_time_inc), get_num_active_workers(), cpu_usage);

            usleep(sleep_micro);
            /**
             * to increase the req frequency,
             * we decrease the sleep time
             */
            sleep_micro /= 2;
            break;

        case CONSTANT:
            //printf(">>> CONSTANT FREQUENCY >>>\n");

            cpu_stats_begin = read_cpu();
            req_time_const = do_request(num_req, id, operation, cookie);
            cpu_stats_end = read_cpu();

            pthread_mutex_lock(&bench_timer_lock);
            time_spent = elapsed_time(&bench_start_time);
            pthread_mutex_unlock(&bench_timer_lock);

            cpu_usage = get_avg_cpu_usage(cpu_stats_end, cpu_stats_begin);
            register_results_dynamic(res_file, time_spent, get_tput(num_req, req_time_const), get_num_active_workers(), cpu_usage);
            /**
             * sleep time remains constant here
             */
            usleep(sleep_micro);

            break;
        case DECREASE:
            //printf(">>> DECREASING FREQUENCY >>>\n");
            cpu_stats_begin = read_cpu();
            req_time_dec = do_request(num_req, id, operation, cookie);
            cpu_stats_end = read_cpu();

            pthread_mutex_lock(&bench_timer_lock);
            time_spent = elapsed_time(&bench_start_time);
            pthread_mutex_unlock(&bench_timer_lock);

            cpu_usage = get_avg_cpu_usage(cpu_stats_end, cpu_stats_begin);
            register_results_dynamic(res_file, time_spent, get_tput(num_req, req_time_dec), get_num_active_workers(), cpu_usage);

            /**
             * sleep time remains constant here
             */
            usleep(sleep_micro);
            /**
             * to decrease the req frequency,
             * we increase the sleep time
             */
            sleep_micro *= 2;
            break;
        default:
            break;
        }

        /**
         * leave the loop
         */
    }
}

/**
 * Perform a read request via an ecall.
 * The time taken for the request to complete is returned.
 * cookie struct contains fd and file path
 */
double do_request(int num_ops, int thread_id, int operation, void *cookie)
{
    struct timespec req_start, req_stop;

    start_clock(&req_start);
    // ecall_do_lmbench_op(global_eid, num_ops, thread_id, operation, cookie);
    ecall_write_kissdb(global_eid, num_ops, thread_id);
    stop_clock(&req_stop);
    double req_time = time_diff(&req_start, &req_stop, SEC);
    //printf(">>> request complete: num_ops: %d thread_id: %d tput: %f OP/s >>\n", num_ops, thread_id, num_ops / req_time);
    return req_time;
}

/**
 * Each thread will create its results file
 */

char *create_results_file(int thread_id)
{
    char *path = (char *)malloc(RES_FILE_LEN);
    // snprintf(path, RES_FILE_LEN, "results_kissdb_dynamic_%d.csv", thread_id);
    snprintf(path, RES_FILE_LEN, "results_lmbench_dynamic_%d.csv", thread_id);
    return path;
}

/**
 * Writes nKeys kv pairs in paldb with nThreads
 * The number of kv pairs will be divided among the number of threads more or less evenly.
 */

void write_bench(int num_keys, int num_threads)
{
    struct thread_args *args = (struct thread_args *)malloc(sizeof(struct thread_args));
    /**
     * Roughly divide the number of keys among the threads
     */
    args->num_keys = num_keys / num_threads;
    args->rw_id = 0;
    pthread_t id[num_threads];

    for (int i = 0; i < num_threads; i++)
    {
        pthread_create(&id[i], NULL, writer_thread, (void *)args);
    }
    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(id[i], NULL);
    }
    free(args);
}

/**
 * simple lmbench --> no dynamic stuff
 */
void lmbench_simple(int num_ops, int num_threads)
{
    int read_threads = num_threads / 2;
    int write_threads = num_threads - read_threads;

    int half_ops = num_ops / 2;

    struct thread_args *reader_args = (struct thread_args *)malloc(sizeof(struct thread_args));
    /**
     * Roughly divide the number of ops among the threads
     */
    reader_args->num_keys = half_ops / read_threads;
    reader_args->rw_id = 0;
    reader_args->run_time = 0;
    reader_args->operation = READ_OP;
    reader_args->file_info = get_read_cookie();

    struct thread_args *writer_args = (struct thread_args *)malloc(sizeof(struct thread_args));
    /**
     * Roughly divide the number of ops among the threads
     */
    writer_args->num_keys = half_ops / write_threads;
    writer_args->rw_id = 1;
    writer_args->run_time = 0;
    writer_args->operation = WRITE_OP;
    writer_args->file_info = get_write_cookie();

    pthread_t id[num_threads];

    pthread_mutex_init(&bench_timer_lock, NULL);

    for (int i = 0; i < read_threads; i++)
    {
        pthread_create(&id[i], NULL, lm_thread, (void *)reader_args);
    }
    for (int i = read_threads; i < num_threads; i++)
    {
        pthread_create(&id[i], NULL, lm_thread, (void *)writer_args);
    }

    /**
     * let all the threads start
     * at approx the same time
     */
    clock_gettime(CLOCK_MONOTONIC_RAW, &bench_start_time);
    start = 1;

    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(id[i], NULL);
    }

    free(reader_args);
    free(writer_args);

    pthread_mutex_destroy(&bench_timer_lock);
}

/**
 * lmbench thread
 */
void *lm_thread(void *input)
{

    wait_for_start();
    int thread_id = __atomic_fetch_add(&write_store_counter, 1, __ATOMIC_RELAXED);
    int num_ops = ((struct thread_args *)input)->num_keys;
    int operation = ((struct thread_args *)input)->operation;
    void *cookie = (void *)((struct thread_args *)input)->file_info;

    ecall_do_lmbench_op(global_eid, num_ops, thread_id, operation, cookie);
}

/**
 * Half of the threads will do reads and the others writes
 */
void bench_dynamic(int num_ops, int num_threads, double run_time)
{
    int read_threads = num_threads / 2;
    int write_threads = num_threads - read_threads;

    int half_ops = num_ops / 2;

    struct thread_args *reader_args = (struct thread_args *)malloc(sizeof(struct thread_args));
    /**
     * Roughly divide the number of ops among the threads
     */
    reader_args->num_keys = half_ops / read_threads;
    reader_args->rw_id = 0;
    reader_args->run_time = run_time;
    reader_args->operation = READ_OP;
    reader_args->file_info = get_read_cookie();

    struct thread_args *writer_args = (struct thread_args *)malloc(sizeof(struct thread_args));
    /**
     * Roughly divide the number of ops among the threads
     */
    writer_args->num_keys = half_ops / write_threads;
    writer_args->rw_id = 1;
    writer_args->run_time = run_time;
    writer_args->operation = WRITE_OP;
    writer_args->file_info = get_write_cookie();

    pthread_t id[num_threads];

    pthread_mutex_init(&bench_timer_lock, NULL);

    for (int i = 0; i < read_threads; i++)
    {
        pthread_create(&id[i], NULL, thread_dynamic, (void *)reader_args);
    }
    for (int i = read_threads; i < num_threads; i++)
    {
        pthread_create(&id[i], NULL, thread_dynamic, (void *)writer_args);
    }

    /**
     * the thread_dynamic routines will begin
     * reading/writing only after start is 1.
     * this helps to prevent lag between the spawned
     * threads as they work with the same global timer.
     */
    clock_gettime(CLOCK_MONOTONIC_RAW, &bench_start_time);
    start = 1;

    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(id[i], NULL);
    }

    free(reader_args);
    free(writer_args);

    pthread_mutex_destroy(&bench_timer_lock);
}

/**
 * Reads nKeys kv pairs in paldb with nThreads
 * The number of keys will be divided among the number of threads more or less evenly.
 */

void read_bench(int num_keys, int num_threads)
{
    struct thread_args *args = (struct thread_args *)malloc(sizeof(struct thread_args));
    /**
     * Roughly divide the number of keys among the threads
     */
    args->num_keys = num_keys / num_threads;
    args->rw_id = 0;
    pthread_t id[num_threads];

    for (int i = 0; i < num_threads; i++)
    {
        pthread_create(&id[i], NULL, reader_thread, (void *)args);
        args->rw_id += 1;
    }
    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(id[i], NULL);
    }
    free(args);
}
