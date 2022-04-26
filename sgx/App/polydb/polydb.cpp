
/*
 * Created on Fri Aug 27 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#include "polydb.h"
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "bench/benchtools.h"

#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>

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
static struct timespec write_start_time;

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

pthread_mutex_t write_timer_lock;

struct thread_args
{
    int num_keys;
    /*read/writer id*/
    int rw_id;
    /*bench time in secs*/
    double run_time;
};

void *reader_thread(void *input)
{
    int n = ((struct thread_args *)input)->num_keys;
    // int id = ((struct thread_args *)input)->rw_id;
    // readers read in the store corresponding to their store id

    // int id = (write_store_counter > 0) ? write_store_counter - 1 : 0;
    int id = __atomic_fetch_add(&read_store_counter, 1, __ATOMIC_RELAXED);

    ecall_readKissdb(global_eid, n, id);
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
    ecall_writeKissdb(global_eid, n, id);
    // ecall_run_fg(global_eid, n, id);
}

/**
 * writer thread routine for dynamic workload
 */
void *writer_thread_dynamic(void *input)
{
    // pthread_mutex_lock(&lock);
    // id = write_store_counter++;
    int id = __atomic_fetch_add(&write_store_counter, 1, __ATOMIC_RELAXED);
    // pthread_mutex_unlock(&lock);

    // cpu usage variables

    unsigned long long **cpu_stats_begin;
    unsigned long long **cpu_stats_end;

    int num_req = ((struct thread_args *)input)->num_keys;

    // probably not the cleanest practice
    unsigned int sleep_micro = static_cast<unsigned int>(max_sleep * MICRO_SECS);

    // workload status: we start at increasing workload
    workload_state state = INCREASE;

    double run_time = ((struct thread_args *)input)->run_time;

    // time thread spends in each state
    double state_slot_time = run_time / NUM_STATES;

    // create results file
    char *res_file = create_results_file(id);

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
            printf(">>> INCREASING FREQUENCY >>>\n");
            /**
             * Send num_req write requests to kissdb in enclave.
             * We could calculate time spent out of the switch
             * block, but I think it makes sense to have it just after
             * performing the requests in each case,
             *  and computing cpu usage during the request period.
             */

            // cpu_stats_begin = read_cpu();
            req_time_inc = do_request(num_req, id);

            pthread_mutex_lock(&write_timer_lock);
            time_spent = elapsed_time(&write_start_time);
            pthread_mutex_unlock(&write_timer_lock);

            register_results_dynamic(res_file, time_spent, num_req / req_time_inc, num_active_zc_workers);

            // cpu_stats_end = read_cpu();
            // cpu_usage = get_avg_cpu_usage(cpu_stats_end, cpu_stats_begin);

            usleep(sleep_micro);
            /**
             * to increase the req frequency,
             * we decrease the sleep time
             */
            sleep_micro /= 2;
            break;

        case CONSTANT:
            printf(">>> CONSTANT FREQUENCY >>>\n");

            req_time_const = do_request(num_req, id);

            pthread_mutex_lock(&write_timer_lock);
            time_spent = elapsed_time(&write_start_time);
            pthread_mutex_unlock(&write_timer_lock);

            register_results_dynamic(res_file, time_spent, num_req / req_time_const, num_active_zc_workers);
            /**
             * sleep time remains constant here
             */
            usleep(sleep_micro);

            break;
        case DECREASE:
            printf(">>> DECREASING FREQUENCY >>>\n");
            req_time_dec = do_request(num_req, id);

            pthread_mutex_lock(&write_timer_lock);
            time_spent = elapsed_time(&write_start_time);
            pthread_mutex_unlock(&write_timer_lock);

            register_results_dynamic(res_file, time_spent, num_req / req_time_dec, num_active_zc_workers);

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
    }
}

/**
 * Perform a write request in kissdb via an ecall.
 * The time taken for the request to complete is returned.
 */
double do_request(int num_keys, int thread_id)
{
    struct timespec req_start, req_stop;

    start_clock(&req_start);
    ecall_writeKissdb(global_eid, num_keys, thread_id);
    stop_clock(&req_stop);
    double req_time = time_diff(&req_start, &req_stop, SEC);
    printf(">>> kissdb write request complete: num_keys: %d thread_id: %d tput: %f OP/s >>\n", num_keys, thread_id, num_keys / req_time);
    return req_time;
}

/**
 * Each thread will create its results file
 */

char *create_results_file(int thread_id)
{
    char *path = (char *)malloc(RES_FILE_LEN);
    snprintf(path, RES_FILE_LEN, "results_kissdb_dynamic_%d.csv", thread_id);
    return path;
}

/**
 * Writes nKeys kv pairs in paldb with nThreads
 * The number of kv pairs will be divided among the number of threads more or less evenly.
 */

void write_keys(int num_keys, int num_threads)
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

void write_keys_dynamic(int num_keys, int num_threads, double run_time)
{
    struct thread_args *args = (struct thread_args *)malloc(sizeof(struct thread_args));
    /**
     * Roughly divide the number of keys among the threads
     */
    args->num_keys = num_keys / num_threads;
    args->rw_id = 0;
    args->run_time = run_time;

    pthread_t id[num_threads];

    pthread_mutex_init(&write_timer_lock, NULL);

    /**
     * a small delta time is spent to spawn the threads in pthread_create,
     * but lets assume writing starts here
     */
    clock_gettime(CLOCK_MONOTONIC_RAW, &write_start_time);

    for (int i = 0; i < num_threads; i++)
    {
        pthread_create(&id[i], NULL, writer_thread_dynamic, (void *)args);
    }
    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(id[i], NULL);
    }
    free(args);

    pthread_mutex_destroy(&write_timer_lock);
}

/**
 * Reads nKeys kv pairs in paldb with nThreads
 * The number of keys will be divided among the number of threads more or less evenly.
 */

void read_keys(int num_keys, int num_threads)
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
