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
#include "zc_ocalls_out.h"

//this contains all the available argument slots for switchless calls
//update: with mem pools this is not needed
zc_arg_list *main_arg_list;

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
static void zc_worker_loop(void);
static int getOptimalWorkers(int);
static void create_zc_worker_threads(int numWorkers);
void *zc_worker_thread(void *input);
static void init_mem_pools();
static void init_pools();
static void free_mem_pools();

//useful globals
int num_cores = -1;

zc_mpool *pools;

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
    init_zc_mpmc_queues();
    //allocate memory pools
    init_pools();
    //create zc switchless worker threads
    //create_zc_worker_threads(numWorkers);
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

void *zc_worker_thread(void *input)
{
    log_zc_routine(__func__);

    printf("---------hello I'm a zc worker and this is a test -----------\n");
    //return;
    //zc_worker_loop();
}

/**
 * Each worker thread loops in here for sometime waiting for pending requests.
 */
static void zc_worker_loop()
{
    log_zc_routine(__func__);

    while (1)
    {
        /**
         * If request queue is non-empty, dequeue and handle request
         */
        if (mpmc_queue_count(&req_mpmcq) > 0)
        {
            void *request;
            zc_mpmc_dequeue(&req_mpmcq, &request);
            handle_zc_switchless_request((zc_req *)request);
        }

        //TODO: sleep or something to save cpu cycles
    }
}

/**
 * pyuhala: Routine to handle switchless routines. Using switch is probably not the smartest way,
 * but OK for a POC with a few shim functions.
 * Try using a function table to resolve the corresponding functions
 */
void handle_zc_switchless_request(zc_req *request)
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
     * and enqueue on response queue
     */
    request->is_done = 1;
    zc_mpmc_enqueue(&resp_mpmcq, (void *)request);
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
    pools = (zc_mpool *)malloc(sizeof(zc_mpool));

    for (int i = 0; i < NUM_POOLS; i++)
    {
        pools->memory_pools[i] = mpool_create(POOL_SIZE);
    }
}

static void free_mem_pools()
{
    for (int i = 0; i < NUM_POOLS; i++)
    {
        mpool_destroy(pools->memory_pools[i]);
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
    for (int i = 0; i < numWorkers; i++)
    {
        pthread_join(*(worker_ids + i), NULL);
    }
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