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

/**
 * Lock free queues for zc switchless calls
 */
extern struct mpmcq req_mpmcq;
extern struct mpmcq resp_mpmcq;

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

//useful globals
int num_cores = -1;

zc_mpool_array *pools;

ssize_t curr_pool_index = 0; /* workers will get the pool at this index */

pthread_mutex_t pool_index_lock;

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
    //init_zc_mpmc_queues();
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
    int thread_pool_index = -1;
    log_zc_routine(__func__);
    pthread_mutex_lock(&pool_index_lock);
    thread_pool_index = curr_pool_index;
    curr_pool_index++;
    pthread_mutex_unlock(&pool_index_lock);

    //printf("---------hello I'm a zc worker and my pool id is: %d -----------\n", thread_pool_index);
    zc_worker_loop(thread_pool_index);
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

    for (;;)
    {
        //printf("xxxxxxxxxxxxxxxxx in worker loop xxxxxxxxxxxxxxxxxxxx\n");

        pool_state = (zc_pool_status)pools->memory_pools[pool_index]->pool_status;
        /**
         * using queues
         */
        /* if (mpmc_queue_count(&req_mpmcq) > 0)
        {
            printf("-------------- mpmpc queue count > 0 -----------------\n");
            void *request;
            zc_mpmc_dequeue(&req_mpmcq, &request);
            handle_zc_switchless_request((zc_req *)request);
        }*/

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
            handle_zc_switchless_request(req, pool_index);
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

        default:
        {
        }
        break;
        }

        //manage memory pool

        //TODO: sleep or something to save cpu cycles
    }
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
        printf("----------- cannot handle zc switchless request -------------\n");
        break;
    }

    /**
     * Finalize request: change its status to done,
     * 
     */
    request->is_done = ZC_REQUEST_DONE;
    pools->memory_pools[pool_index]->pool_status = (int)WAITING;

    //zc_mpmc_enqueue(&resp_mpmcq, (void *)request);
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
        pools->memory_pools[i]->active = 0; /* it hasn't been allocated to a thread yet */
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
    for (int i = 0; i < numWorkers; i++)
    {

        pthread_create(worker_ids + i, NULL, zc_worker_thread, NULL);
    }

    /* for (int i = 0; i < numWorkers; i++)
    {
        printf(" -------------- zc worker thread: %d ----------------\n", *(worker_ids + i));
    }*/

    // pyuhala: joining not a good idea.. since these threads loop "infinitely"
    /* for (int i = 0; i < numWorkers; i++)
    {
        pthread_join(*(worker_ids + i), NULL);
    }*/
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