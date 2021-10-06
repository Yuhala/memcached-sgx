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

//zc_arg_list *main_arg_list;

//pyuhala: some useful global variables
extern sgx_enclave_id_t global_eid;

//zc switchless worker thread ids
pthread_t *worker_ids;

//number of completed switchless requests
unsigned int completed_switchless_requests = 0;

//number of initialized workers
static unsigned int num_init_worker = 0;

//number of requests on the request queue
extern volatile unsigned int num_items;

/**
 * Lock free queues for zc switchless calls
 */
extern struct mpmcq *req_mpmcq;
extern struct mpmcq *resp_mpmcq;

//pyuhala: forward declarations
static void zc_worker_loop(int);
static int getOptimalWorkers(int);
static void create_zc_worker_threads(int numWorkers);
void *zc_worker_thread(void *input);
void *zc_scheduler_thread(void *input);
static void init_mem_pools();
static void init_pools();
static void free_mem_pools();
static void init_zc_scheduler(int num_workers);
static void zc_worker_loop_q();

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

void init_zc(int numWorkers)
{
    log_zc_routine(__func__);
    //get the number of cores on the cpu; this may be bad if these cores are already "strongly taken"
    num_cores = get_nprocs();
    if (num_cores < 1)
    {
        fprintf(stderr, "Insufficient number of CPUs for zc switchless:\n%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    int opt_worker = getOptimalWorkers(numWorkers);

    //init_arg_buffers_out(opt_worker);

    if (use_queues)
    {
        init_zc_mpmc_queues();
    }
    //allocate memory pools
    init_pools();
    //init locks
    pthread_mutex_init(&pool_index_lock, NULL);
    //launch scheduler thread
    create_zc_worker_threads(numWorkers);
    //create zc switchless worker threads
}

static void init_zc_scheduler(int num_workers)
{
    //TODO
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
    ecall_init_mem_pools(global_eid, (void *)pools);
}

void *zc_scheduler_thread(void *input)
{
    //TODO
}

void *zc_worker_thread(void *input)
{
    log_zc_routine(__func__);

    //printf("---------hello I'm a zc worker and my pool id is: %d -----------\n", thread_pool_index);
    if (use_queues)
    {
        zc_worker_loop_q();
    }
    else
    {
        //use worker thread buffers/pool system
        zc_worker_args *args = (zc_worker_args *)input;
        zc_worker_loop(args->pool_index);
    }
}

/**
 * Each worker thread loops in here for sometime waiting for pending requests.
 */
static void zc_worker_loop(int index)
{
    log_zc_routine(__func__);
    //set pool states

    int pool_index = index;
    pools->memory_pools[pool_index]->active = 1; /* pool is assigned to this thread */
    pools->memory_pools[pool_index]->request = NULL;
    pools->memory_pools[pool_index]->pool_status = (int)UNUSED;
    volatile zc_pool_status pool_state;
    volatile int status;

    // worker initialization complete
    int val = __atomic_fetch_add(&num_init_worker, 1, __ATOMIC_RELAXED);

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
                goto resume;
            }
            handle_zc_switchless_request(req, pool_index);
            //remove this request from this pool
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
            //TODO: exit thread
        }
        break;
        }

    resume:;

        //manage memory pool

        //TODO: sleep or something to save cpu cycles
    }
    //printf("xxxxxxxxxxxxxxxxxxxxx ------------------zc thread broke out of infinite loop -------------------xxxxxxxxxxxxxxxxxxxxxxxxxxx\n");
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
    int val = __atomic_fetch_add(&num_init_worker, 1, __ATOMIC_RELAXED);
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
    __atomic_store_n(&request->is_done, ZC_REQUEST_DONE, __ATOMIC_SEQ_CST); /* with atomic store */

    if (pool_index != -1)
    {
        // we do not do this for the queue system; callers find any free pools for arg allocation, independent of workers
        //__atomic_store_n(&pools->memory_pools[pool_index]->pool_status, (int)WAITING, __ATOMIC_RELAXED);
    }

    //pools->memory_pools[pool_index]->pool_status = (int)WAITING;
    //pyuhala: doing below for debug reasons..something's not alright
    //request->req_pool_index = pool_index;

    //count switchless calls
    int val = __atomic_add_fetch(&completed_switchless_requests, 1, __ATOMIC_RELAXED);
    //print for every 10 switchless requests
    /*
    if (!(val % 10))
    {
        printf(">>>>>>>>>>>>>>>> num complete switchless calls: %d >>>>>>>>>>>>>>>>>>>>>\n", val);
    }*/
}

static int getOptimalWorkers(int numWorkers)
{
    //TODO
    return numWorkers;
}

/**
 * Preallocate untrusted  memory that will be used by enclave threads
 * to allocate requests and pass arguments.
 */

static void init_mem_pools()
{
    pools = (zc_mpool_array *)malloc(sizeof(zc_mpool_array));
    pools->memory_pools = (zc_mpool **)malloc(sizeof(zc_mpool *) * NUM_POOLS);

    //initializing memory pools
    printf("<<<<<<<<<<<<<<< initializing memory pools >>>>>>>>>>>>>>>>\n");

    for (int i = 0; i < NUM_POOLS; i++)
    {
        pools->memory_pools[i] = (zc_mpool *)malloc(sizeof(zc_mpool));
        pools->memory_pools[i]->pool = mpool_create(POOL_SIZE);
        pools->memory_pools[i]->pool_id = i;

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

static void free_mem_pools()
{
    for (int i = 0; i < NUM_POOLS; i++)
    {
        mpool_destroy(pools->memory_pools[i]->pool);
    }

    free(pools);
}

static void create_zc_worker_threads(int numWorkers)
{
    worker_ids = (pthread_t *)malloc(sizeof(pthread_t) * numWorkers);

    zc_worker_args *args;
    for (int i = 0; i < numWorkers; i++)
    {
        args = (zc_worker_args *)malloc(sizeof(zc_worker_args));
        args->pool_index = curr_pool_index++;

        pthread_create(worker_ids + i, NULL, zc_worker_thread, (void *)args);
    }

    // pyuhala: joining not a good idea.. since these threads loop "infinitely"
    /* for (int i = 0; i < numWorkers; i++)
    {
        pthread_join(*(worker_ids + i), NULL);
    }*/

    // wait for workers to initialize
    while (num_init_worker < numWorkers)
    {
        ZC_PAUSE();
    }
}

void finalize_zc()
{
    //stop all zc threads

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