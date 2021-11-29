/*
 * Created on Wed Sep 29 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#include "Enclave_u.h"
#include "sgx_urts.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <pthread.h>
#include <signal.h>

#include <errno.h>
#include "zc_logger.h"

#include "zc_out.h"
#include "memcached/mpool.h"
#include "zc_ocalls_out.h"

#include "zc_locks.h"

#include "scheduler.h"
#include <sched.h>

#define _BSD_SOURCE
#include <sys/time.h>
#include <time.h>

#define NANO (1000 * 1000 * 1000)

//zc_arg_list *main_arg_list;

//pyuhala: some useful global variables
extern sgx_enclave_id_t global_eid;

//zc switchless worker thread ids
pthread_t *workers;

// statistics of the switchless run
zc_stats *zc_statistics;

//number of initialized workers
unsigned int num_workers = 0;
unsigned int num_initialized_workers = 0;

// cpu frequency in MHz
int cpu_freq;

//number of requests on the request queue
extern volatile unsigned int num_items;

//globals from scheduler module
//extern int time_quantum;
//extern int number_of_useful_schedulings;

bool use_zc_scheduler = false;

bool set_worker_priorities = false;

static __thread int sl_calls_treated;
/**
 * Lock free queues for zc switchless calls
 */
extern struct mpmcq *req_mpmcq;
extern struct mpmcq *resp_mpmcq;

//pyuhala: forward declarations
static void zc_worker_loop(zc_worker_args *args);
static int getOptimalWorkers(int);
static void create_zc_worker_threads();
void *zc_worker_thread(void *input);
void *zc_scheduler_thread(void *input);
static void init_mem_pools();
static void init_pools();
static void free_mem_pools();
static void zc_worker_loop_q();
static bool could_have_pending_request(int pool_index);
static void refresh_paused_worker(int index);
static void wait_for_pool_release(int index);
static void set_worker_priority(pthread_attr_t *attr, int priority);

static inline void asm_pause(void);

//for scheduler
void zc_create_scheduling_thread();

//useful globals
int num_cores = -1;

zc_mpool_array *pools;

ssize_t curr_pool_index = 0; /* workers will get the pool at this index */

pthread_mutex_t pool_index_lock;

static bool use_queues = false;

/**
 * Initializes zc switchless system using this number of worker threads out of the enclave
 * to service ocalls. Future work: implement zc for ecalls.
 */

void init_zc(int num_sl_workers)
{

    log_zc_routine(__func__);
    //get the number of cores on the cpu; this may be bad if these cores are already "strongly taken"
    num_cores = get_nprocs();
    /* if (num_cores < 1)
    {
        fprintf(stderr, "Insufficient number of CPUs for zc switchless:\n%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    } */

    printf("<<<<<<<<<<<<<<<<< number of cores found: %d >>>>>>>>>>>>>>>>>>>\n", num_cores);
    //num_workers = num_cores / 2;

    num_workers = num_sl_workers;

    cpu_freq = get_cpu_freq();

    printf("CPU frequency: %d MHz >>>>>>>>>>>>>\n", cpu_freq);

    // make sure num of default pools >= num of workers
    //ZC_ASSERT(numWorkers <= NUM_POOLS);

    //init_arg_buffers_out(opt_worker);

    if (use_queues)
    {
        init_zc_mpmc_queues();
    }

    // initialize zc stats
    zc_statistics = (zc_stats *)malloc(sizeof(zc_stats));
    zc_statistics->num_zc_swtless_calls = 0;
    zc_statistics->num_zc_fallback_calls = 0;
    zc_statistics->max_workers = num_workers;

    //allocate memory pools
    init_pools();

    //init locks
    pthread_mutex_init(&pool_index_lock, NULL);

    //create zc switchless worker threads
    create_zc_worker_threads();

    //create scheduling thread
    if (use_zc_scheduler)
    {
        //zc_create_scheduling_thread();
        init_zc_scheduler();
    }
}

/**
 * Initialize untrusted memory pools which will be 
 * used by enclave threads for untrusted memory allocations (for arguments, request buffers etc)
 */
static void init_pools()

{
    log_zc_routine(__func__);

    //allocate memory pools
    init_mem_pools();

    //send main_arg_list and memory pools handle to the enclave
    ecall_init_mem_pools(global_eid, (void *)pools, (void *)zc_statistics);
}

/**
 * Preallocate untrusted  memory that will be used by enclave threads
 * to allocate requests and pass arguments.
 */

static void init_mem_pools()
{
    int n = num_workers;
    pools = (zc_mpool_array *)malloc(sizeof(zc_mpool_array));
    pools->memory_pools = (zc_mpool **)malloc(sizeof(zc_mpool *) * n);
    pools->num_pools = n;

    //initializing memory pools
    printf("<<<<<<<<<<<<<<< initializing memory pools >>>>>>>>>>>>>>>>\n");

    for (int i = 0; i < n; i++)
    {
        pools->memory_pools[i] = (zc_mpool *)malloc(sizeof(zc_mpool));
        pools->memory_pools[i]->pool = mpool_create(POOL_SIZE);
        pools->memory_pools[i]->pool_id = i;
        pools->memory_pools[i]->pool->mpool_id = i;
        pools->memory_pools[i]->pool_lock = 0;
        pools->memory_pools[i]->pool_status = (int)INACTIVE;

        if (use_queues)
        {
            /**
             * pyuhala: when using queues, the memory pools are simply used by
             * in-enclave threads for untrusted mem allocation independent of 
             * worker threads. The worker threads only dequeue and handle requests.
             * So activate all the pools.
             */
            pools->memory_pools[i]->active = 1;
        }
        else
        {
            /**
             * when using our per-worker buffer/pool system, each worker 
             * "owns" a pool and this active status will be set only when a 
             * corresponding worker is created, so we don't have caller threads
             * using pools w/o a worker.
             */
            pools->memory_pools[i]->active = 0;
        }
    }
}

/**
 * Pool is full, release all pool memory
 * and reallocate some memory for it.
 */

void *ocall_free_reallocate_pool(unsigned int id)
{
    // free memory
    mpool_destroy(pools->memory_pools[id]->pool);
    // reallocate

    mpool_t *new_pool = mpool_create(POOL_SIZE);
    ZC_ASSERT(new_pool != NULL);

    pools->memory_pools[id]->pool = new_pool;
    // reassign same id
    pools->memory_pools[id]->pool->mpool_id = id;

    return (void *)new_pool;
}

void *zc_worker_thread(void *input)
{
    log_zc_routine(__func__);

    //register signal handler
    signal(ZC_SIGNAL, zc_signal_handler);

    /*  if (use_queues)
    {
        zc_worker_loop_q();
    } */

    //use worker thread buffers/pool system
    zc_worker_args *args = (zc_worker_args *)input;
    zc_worker_loop(args);
}

/**
 * This function "refreshes" a paused worker. That is:
 * the worker resets the necessary variables (e.g buffer status etc) to make it
 * available again to callers. Only called by workers. 
 */
static void refresh_paused_worker(int index)
{

    __atomic_store_n(&pools->memory_pools[index]->pool_status, (int)UNUSED, __ATOMIC_SEQ_CST);
    __atomic_store_n(&pools->memory_pools[index]->active, 1, __ATOMIC_SEQ_CST);
    __atomic_store_n(&pools->memory_pools[index]->scheduler_pause, 0, __ATOMIC_SEQ_CST);
}

/**
 * Waits for a caller to release the buffer
 */
static void wait_for_pool_release(int index)
{
    while (__atomic_load_n(&pools->memory_pools[index]->pool_status, __ATOMIC_RELAXED) != (int)DONE)
    {
        asm_pause();
    }
}

/**
 * Each worker thread loops in here for sometime waiting for pending requests.
 */
static void zc_worker_loop(zc_worker_args *args)
{
    log_zc_routine(__func__);
    printf("-------------------beginning thread worker loop ------------------->>>>>>>>>>>>>\n");
    struct sched_param param;
    /* setting the worker's priority to a high priority */

    if (use_zc_scheduler && false)
    {
        param.sched_priority = 50;
        if (sched_setscheduler(0, SCHED_RR, &param) == -1)
        {
            printf("Unable to change the policy of a worker thread to SCHED_RR\n");
            //perror("Unable to change the policy of a worker thread to SCHED_RR");
            //exit(1);
        }
    }

    int unused = (int)UNUSED;
    int paused = (int)PAUSED;
    bool res = false;

    int worker_id = args->worker_id;

    int pool_index = args->pool_index;
    pools->memory_pools[pool_index]->request = NULL;

    //pools->memory_pools[pool_index]->pool_status = (int)UNUSED;
    //pools->memory_pools[pool_index]->active = 1; /* pool is assigned to this thread */

    //pools->memory_pools[pool_index]->scheduler_pause = 0;
    volatile zc_pool_status pool_state;
    volatile int status;
    volatile int state;
    bool exit = false;
    volatile int pause_test;

    // worker initialization complete
    int val = __atomic_fetch_add(&num_initialized_workers, 1, __ATOMIC_RELAXED);

    for (;;)
    {

        state = __atomic_load_n(&pools->memory_pools[pool_index]->pool_status, __ATOMIC_RELAXED);
        //pool_state = (zc_pool_status)pools->memory_pools[pool_index]->pool_status;
        pool_state = (zc_pool_status)state;

        /**
         * Check pool states
         */
        switch (pool_state)
        {

        case UNUSED:
        {
            /**
             * TODO: pyuhala: this case causes issues at the level of pause. i.e sometimes a worker treating a request is paused.
             * I avoid this by just short-circuiting the whole test for now.
             */

            goto leave;
            /**
         * Check for pause signal from scheduler. Compare and swap
         * atomically in case the buffer is unused. Atomic compare and swap important
         * to prevent caller inside from reserving at the same time.
         *
         */
            if (__atomic_load_n(&pools->memory_pools[pool_index]->scheduler_pause, __ATOMIC_RELAXED) == 1)
            {
                //printf("--------------------------- worker scheduled to  pause ------------------------\n");
                bool success = __atomic_compare_exchange_n(&pools->memory_pools[pool_index]->pool_status,
                                                           &unused, paused, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
                /**
             * Pause worker only if we succeeded in setting the pool status to PAUSED.
             * Otherwise, maybe a caller already reserved atomically. We will/may only
             * pause after it sets the status to DONE.
             */
                if (success)
                {
                    __atomic_store_n(&pools->memory_pools[pool_index]->active, 0, __ATOMIC_SEQ_CST);

                    pause();
                    // I'm done pausing; refresh my state
                    refresh_paused_worker(pool_index);
                }
            }
        leave:;
        }

        break;
        case INACTIVE:
        {

            /* we are at program start, activate the pool*/
            printf("-->>>>>>>>>>> activating inactive pool >>>>>>>>>>>>>>>>\n");

            __atomic_store_n(&pools->memory_pools[pool_index]->pool_status, (int)UNUSED, __ATOMIC_SEQ_CST);
            __atomic_store_n(&pools->memory_pools[pool_index]->active, 1, __ATOMIC_SEQ_CST);
            __atomic_store_n(&pools->memory_pools[pool_index]->scheduler_pause, 0, __ATOMIC_SEQ_CST);
        }
        break;

        case PROCESSING: /* caller is done setting up request, call the corresponding routine */
        {
            //printf("------zc worker handling a request--------\n");
            zc_req *req = pools->memory_pools[pool_index]->request;
            /**
             * pyuhala: if req = NULL, pause and try again
             */
            if (req == NULL)
            {
                //printf("------------ null or stale request -------------\n");
                //goto resume;
                break;
            }
            //don't treat stale request
            else
            {
                if (req->req_status != STALE_REQUEST)
                {
                    handle_zc_switchless_request(req, pool_index);
                    // caller thread is waiting for this unlock
                    //zc_spin_unlock(&req->is_done);
                    req->req_status = STALE_REQUEST;
                    sl_calls_treated++;
                    /**
                     * Wait for caller to complete.
                     * pyuhala: to be remove.. not really needed
                     */
                    //wait_for_pool_release(pool_index);
                }
            }
        }
        break;

        case DONE:
        {
            /**
             * A caller has released this buffer. Check for pause signal from scheduler.
             * If pause is set, pause. Otherwise set the state to UNUSED so other callers
             * can use this buffer. Only callers set this. Pausing/activating in here is safe b/c we 
             * are 100% sure the last caller using this buffer completed its work.
             */

            if (__atomic_load_n(&pools->memory_pools[pool_index]->scheduler_pause, __ATOMIC_RELAXED) == 1)
            {

                __atomic_store_n(&pools->memory_pools[pool_index]->pool_status, (int)PAUSED, __ATOMIC_SEQ_CST);
                __atomic_store_n(&pools->memory_pools[pool_index]->active, 0, __ATOMIC_SEQ_CST);

                pause();
                // I'm done pausing; refresh my state
                refresh_paused_worker(pool_index);
            }
            else
            {
                /**
                 * Worker not scheduled to pause, set buffer state to UNUSED and resume loop.
                 * resume loop.
                 */
                __atomic_store_n(&pools->memory_pools[pool_index]->pool_status, (int)UNUSED, __ATOMIC_SEQ_CST);
                //goto resume_loop;
            }
        }
        break;

        case EXIT:

        {
            /* worker should exit */
            exit = true;
        }
        break;

        } //end switch case

        if (exit)
        {
            //leave while loop
            break;
        }

    resume_loop:;
    }
    printf("\e[0;31mnumber of switchless calls treated by worker %d : %d\e[0m\n", worker_id, sl_calls_treated);
}

/**
 * signal handler to wake sleeping threads
 */
void zc_signal_handler(int sig)
{
    //printf("Thread caught signal %d\n", sig);
    //do nothing
}

/**
 * Check if there is a pending request in the buffer
 */
static bool could_have_pending_request(int pool_index)
{
    bool test = false;
    // pyuhala: I don't think there is any use for locks here.
    //zc_spin_lock(&pools->memory_pools[pool_index]->pool_lock);
    if (pools->memory_pools[pool_index]->request != NULL)
    {
        if (pools->memory_pools[pool_index]->request->req_status != STALE_REQUEST)
        {
            // This is a real pending request and is not stale
            test = true;
        }
    }
    //zc_spin_unlock(&pools->memory_pools[pool_index]->pool_lock);

    return test;
}

/**
 * Each worker thread loops in here for sometime waiting for pending requests.
 * Implementation with mpmc request queue
 */
static void zc_worker_loop_q()
{
    log_zc_routine(__func__);
    //set pool states

    // worker initialization complete
    int val = __atomic_fetch_add(&num_workers, 1, __ATOMIC_RELAXED);
    zc_req *request = NULL;

    for (;;)
    {

        ZC_PAUSE();

        /**
         * using queues
         */
        if (mpmc_queue_count(req_mpmcq) > 0)
        {

            int ret = mpmc_dequeue(req_mpmcq, (void **)&request);
            if (ret == 1)
            {
                //printf("------------------- request dequeued ----------------\n");
            }
            handle_zc_switchless_request(request, -1);
        }

        //TODO: sleep or something to save cpu cycles
    }
    //printf("xxxxxxxxxxxxxxxxxxxxx ------------------zc thread broke out of infinite loop -------------------xxxxxxxxxxxxxxxxxxxxxxxxxxx\n");
}

/**
 * pyuhala: Routine to handle switchless routines. Using switch is probably not the smartest way,
 * but OK for a POC with a few shim functions.
 * Try using a function table to resolve the corresponding functions
 * Change status of the pool when done
 */
void handle_zc_switchless_request(zc_req *request, int pool_index)
{
    switch (request->func_name)
    {
    case ZC_FREAD:
        zc_fread_switchless(request);
        break;

    case ZC_FWRITE:
        zc_fwrite_switchless(request);
        break;

    case ZC_READ:
        zc_read_switchless(request);
        break;

    case ZC_WRITE:
        zc_write_switchless(request);
        break;

    case ZC_SENDMSG:
        zc_sendmsg_switchless(request);
        break;

    case ZC_FSEEKO:
        zc_fseeko_switchless(request);
        break;

    case ZC_TRANSMIT_PREPARE:
        zc_transmit_prepare(request);
        break;

    case ZC_FSYNC:
        zc_fsync_switchless(request);
        break;
    case ZC_SYNC:
        zc_sync_switchless(request);
        break;
    case ZC_FTRUNCATE64:
        zc_ftruncate64_switchless(request);
        break;

    case ZC_TEST:
        zc_test_switchless(request);
        break;

    default:
        //printf("----------- cannot handle zc switchless request -------------\n");
        break;
    }

    /**
     * Finalize request: change its status to done,
     * 
     */

    //request->is_done = ZC_REQUEST_DONE; /* w/o atomic store */
    __atomic_store_n(&request->is_done, ZC_REQUEST_DONE, __ATOMIC_SEQ_CST); /* with atomic store */

    if (pool_index != -1)
    {
        // we do not do this for the queue system; callers find any free pools for arg allocation, independent of workers
        //__atomic_store_n(&pools->memory_pools[pool_index]->pool_status, (int)WAITING, __ATOMIC_RELAXED);
    }
}

static void free_mem_pools()
{
    int n = num_cores / 2;

    for (int i = 0; i < n; i++)
    {
        mpool_destroy(pools->memory_pools[i]->pool);
    }

    free(pools);
}

static void create_zc_worker_threads()
{
    workers = (pthread_t *)malloc(sizeof(pthread_t) * num_workers);

    ZC_ASSERT(num_workers <= NUM_POOLS);
    printf("--------------- Num of ZC worker threads: %d ----------------\n", num_workers);

    zc_worker_args *args;
    for (int i = 0; i < num_workers; i++)
    {

        args = (zc_worker_args *)malloc(sizeof(zc_worker_args));
        args->pool_index = i; //curr_pool_index++;
        args->worker_pool = pools->memory_pools[i];
        args->worker_id = i;

        if (set_worker_priorities)
        {
            pthread_attr_t worker_attr;
            set_worker_priority(&worker_attr, ZC_WORKER_PRIORITY);
            pthread_create(workers + i, &worker_attr, zc_worker_thread, (void *)args);
        }
        else
        {
            pthread_create(workers + i, NULL, zc_worker_thread, (void *)args);
        }
    }

    /**
     * pyuhala: wait for workers to initialize.
     * I don't want the main thread spawning callers when workers are 
     * not yet set
     */
    while (num_initialized_workers < num_workers)
    {
        ZC_PAUSE();
    }
}

static void set_worker_priority(pthread_attr_t *attr, int priority)
{
    int ret;
    sched_param param;
    /* initialized w/ default attributes */
    ret = pthread_attr_init(attr);

    /* safe to get existing scheduling param */
    ret = pthread_attr_getschedparam(attr, &param);

    /* set the priority; others are unchanged */
    param.sched_priority = priority;

    /* setting the new scheduling param */
    ret = pthread_attr_setschedparam(attr, &param);

    // call this method just b4 pthread_create
}

void finalize_zc()
{
    //print stats
    //printf("number of useful schedulings : %d\n", number_of_useful_schedulings);
    //printf("time_quantum : %d\n", time_quantum);

    //stop all zc threads
    for (int i = 0; i < num_cores / 2; i++)
    {
        pools->memory_pools[i]->pool_status = (int)EXIT;
        pthread_kill(workers[i], SIGALRM);
        if (pthread_join(workers[i], NULL) != 0)
        {
            fprintf(stderr, "Error joining worker thread number %d, exiting\n", i);
            exit(1);
        }
    }

    //deallocate mem pools
    free_mem_pools();
}

/**
 * estimate cpu frequency
 */
int get_cpu_freq()
{
    struct timezone tz;
    struct timeval tvstart, tvstop;
    struct timespec start, stop;
    unsigned long long int cycles[2];
    unsigned long microseconds;
    unsigned long nanoseconds;
    double val;
    int cpu_freq_mhz = DEFAULT_CPU_FREQ;

    //memset(&tz, 0, sizeof(tz));

    clock_gettime(CLOCK_MONOTONIC_RAW, &start);
    //gettimeofday(&tvstart, NULL);
    cycles[0] = rdtscp();
    //gettimeofday(&tvstart, NULL);
    clock_gettime(CLOCK_MONOTONIC_RAW, &start);

    usleep(250000);

    clock_gettime(CLOCK_MONOTONIC_RAW, &stop);
    //gettimeofday(&tvstop, NULL);
    cycles[1] = rdtscp();
    //gettimeofday(&tvstop, NULL);
    clock_gettime(CLOCK_MONOTONIC_RAW, &stop);

    //microseconds = ((tvstop.tv_sec - tvstart.tv_sec) * 1000000) + (tvstop.tv_usec - tvstart.tv_usec);

    nanoseconds = ((stop.tv_sec - start.tv_sec) * 1.0e9) + (stop.tv_nsec - start.tv_nsec);

    val = (double)(cycles[1] - cycles[0]) / (nanoseconds / 1.0e3);

    //printf("%f MHz\n", val);

    cpu_freq_mhz = (int)val;

    return cpu_freq_mhz;
}

static inline void asm_pause(void)
{
    __asm__ __volatile__("pause"
                         :
                         :
                         : "memory");
}

#define ZC_LOGGING 1
#undef ZC_LOGGING

void log_zc_routine(const char *func)
{
#ifdef ZC_LOGGING
    printf("ZC untrusted function: %s\n", func);
#else
//do nothing
#endif
}