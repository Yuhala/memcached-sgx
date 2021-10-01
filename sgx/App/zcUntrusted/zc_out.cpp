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

//this contains all the available argument slots for switchless calls
//update: with mem pools this is not needed
zc_arg_list *main_arg_list;

//pyuhala: some useful global variables
extern sgx_enclave_id_t global_eid;

/**
 * Lock free queues for zc switchless calls
 */
extern volatile struct mpmcq *req_mpmcq;
extern volatile struct mpmcq *resp_mpmcq;

//pyuhala: forward declarations
static void worker_loop(void);
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
    init_pools();
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
}

/**
 * Each worker thread loops in here for sometime waiting for pending requests.
 */
static void worker_loop()
{
    log_zc_routine(__func__);
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