/*
 * Created on Wed Sep 29 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#include "Enclave_u.h"
#include "sgx_urts.h"

#include <time.h>
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

//#include "zc_scheduler.h"

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

//number of requests on the request queue
extern volatile unsigned int num_items;

//globals from scheduler module
extern int time_quantum;
extern int number_of_useful_schedulings;

bool use_zc_scheduler = false;

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
static void init_zc_scheduler();
static void zc_worker_loop_q();

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

void init_zc()
{
    //use_zc_scheduler = true;

    log_zc_routine(__func__);
    //get the number of cores on the cpu; this may be bad if these cores are already "strongly taken"
    num_cores = get_nprocs();
    if (num_cores < 1)
    {
        fprintf(stderr, "Insufficient number of CPUs for zc switchless:\n%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    printf("<<<<<<<<<<<<<<<<< number of cores found: %d >>>>>>>>>>>>>>>>>>>\n", num_cores);
    num_workers = num_cores / 2;

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

    //allocate memory pools
    init_pools();

    //init locks
    pthread_mutex_init(&pool_index_lock, NULL);

    //create zc switchless worker threads
    create_zc_worker_threads();

    //create scheduling thread
    if (use_zc_scheduler)
    {
        zc_create_scheduling_thread();
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
    int n = NUM_POOLS;
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
        pools->memory_pools[i]->pool_lock = 0;

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

void *zc_worker_thread(void *input)
{
    log_zc_routine(__func__);

    if (use_queues)
    {
        zc_worker_loop_q();
    }
    else
    {
        //use worker thread buffers/pool system
        zc_worker_args *args = (zc_worker_args *)input;
        zc_worker_loop(args);
    }
}

/**
 * Each worker thread loops in here for sometime waiting for pending requests.
 */
static void zc_worker_loop(zc_worker_args *args)
{
    log_zc_routine(__func__);

    struct sched_param param;
    /* setting the worker's priority to a high priority */

    if (use_zc_scheduler)
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
    pools->memory_pools[pool_index]->active = 1; /* pool is assigned to this thread */
    pools->memory_pools[pool_index]->request = NULL;
    pools->memory_pools[pool_index]->pool_status = (int)UNUSED;
    volatile zc_pool_status pool_state;
    volatile int status;
    bool exit = false;

    // worker initialization complete
    int val = __atomic_fetch_add(&num_initialized_workers, 1, __ATOMIC_RELAXED);

    for (;;)
    {

        //ZC_PAUSE();
        //printf("xxxxxxxxxxxxxxxxx in worker loop xxxxxxxxxxxxxxxxxxxx\n");
        //status = __atomic_load_n(&pools->memory_pools[pool_index]->pool_status, __ATOMIC_SEQ_CST);
        pool_state = (zc_pool_status)pools->memory_pools[pool_index]->pool_status;
        //pool_state = (zc_pool_status)status;

        /**
         * using per thread memory pools
         */
        switch (pool_state)
        {
        case UNUSED:
        {
            /* do nothing.. no caller needs me */
        }
        break;

        case RESERVED:
        {
            /* do nothing, but a caller is setting up a switchless request */
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
                    zc_spin_unlock(&req->is_done);
                    req->req_status = STALE_REQUEST;
                    sl_calls_treated++;
                }
            }
        }
        break;

        case WAITING:
        {
            /* do nothing.. probably should not be here */
        }
        break;
        case EXIT:

        {
            /* worker should exit */
            exit = true;
        }
        break;
        } //end switch case

        // test for unused buffers

        if (use_zc_scheduler)
        {
            if (worker_id >= num_workers && pools->memory_pools[pool_index]->pool_status == (int)UNUSED)
            {
                // lock, test again, and change status
                zc_spin_lock(&pools->memory_pools[pool_index]->pool_lock);

                res = __atomic_compare_exchange_n(&pools->memory_pools[pool_index]->pool_status,
                                                  &unused, paused, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);

                if (!res)
                {
                    //could not change status of buffer.. resume loop
                    zc_spin_unlock(&pools->memory_pools[pool_index]->pool_lock);
                    goto resume;
                }

                pause();
                if (pools->memory_pools[pool_index]->pool_status == (int)PAUSED)
                {
                    res = __atomic_compare_exchange_n(&pools->memory_pools[pool_index]->pool_status,
                                                      &paused, unused, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
                }
                zc_spin_unlock(&pools->memory_pools[pool_index]->pool_lock);
            }
        }

    resume:;

        if (exit)
        {
            //leave while loop
            break;
        }
    }
    printf("\e[0;31mnumber of switchless calls treated by worker %d : %d\e[0m\n", worker_id, sl_calls_treated);
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

    /**
     * pyuhala: from cpp ref
     * you can look at this store as a producer updating the request state so 
     * i use a mem order release. The caller in the enclave will use mem order acquire
     * and so is guaranteed to see this change... this is my understanding
     */

    //request->is_done = ZC_REQUEST_DONE; /* w/o atomic store */
    //__atomic_store_n(&request->is_done, ZC_REQUEST_DONE, __ATOMIC_SEQ_CST); /* with atomic store */

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

        pthread_create(workers + i, NULL, zc_worker_thread, (void *)args);
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

void finalize_zc()
{
    //print stats
    printf("number of useful schedulings : %d\n", number_of_useful_schedulings);
    printf("time_quantum : %d\n", time_quantum);

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