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
zc_arg_list *main_arg_list;

//pyuhala:some useful global variables
extern sgx_enclave_id_t global_eid;

extern zc_req_q *req_queue;
extern zc_resp_q *resp_queue;

//pyuhala:forward declarations
static void worker_loop(void);
static int getOptimalWorkers(int);
static void init_arg_buffers();
static void create_zc_worker_threads(int numWorkers);
void *zc_worker_thread(void *input);
static void init_mem_pools();
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
    init_zc_queues();
    init_arg_buffers();
}

/**
 * Allocate memory for argument buffers.
 * This routine could get a little tricky. Make sure to free all memory afterwards
 * This is a temporary implem for the poc, thinking of a more generic implem.
 * pyuhala: update: maybe we don't need to do this anymore; memory pools should prevent this confusing "preallocation"
 */
static void init_arg_buffers()

{
    log_zc_routine(__func__);

    main_arg_list = (zc_arg_list *)malloc(sizeof(zc_arg_list));
    // allocate fread arg buffers
    main_arg_list->fread_arg_array = (fread_arg_zc *)malloc(sizeof(fread_arg_zc) * ZC_QUEUE_CAPACITY);
    for (int i = 0; i < ZC_QUEUE_CAPACITY; i++)
    {
        main_arg_list->fread_arg_array[i].buf = malloc(ZC_BUFFER_SZ);
        main_arg_list->fread_arg_array[i].request_id = ZC_FREE_ID;
    }

    // allocate fwrite arg buffers
    main_arg_list->fwrite_arg_array = (fwrite_arg_zc *)malloc(sizeof(fwrite_arg_zc) * ZC_QUEUE_CAPACITY);
    for (int i = 0; i < ZC_QUEUE_CAPACITY; i++)
    {
        main_arg_list->fwrite_arg_array[i].buf = malloc(ZC_BUFFER_SZ);
        main_arg_list->fwrite_arg_array[i].request_id = ZC_FREE_ID;
    }

    // allocate read arg buffers
    main_arg_list->read_arg_array = (read_arg_zc *)malloc(sizeof(read_arg_zc) * ZC_QUEUE_CAPACITY);
    for (int i = 0; i < ZC_QUEUE_CAPACITY; i++)
    {
        main_arg_list->read_arg_array[i].buf = malloc(ZC_BUFFER_SZ);
        main_arg_list->read_arg_array[i].request_id = ZC_FREE_ID;
    }

    // allocate write arg buffers
    main_arg_list->write_arg_array = (write_arg_zc *)malloc(sizeof(write_arg_zc) * ZC_QUEUE_CAPACITY);
    for (int i = 0; i < ZC_QUEUE_CAPACITY; i++)
    {
        main_arg_list->write_arg_array[i].buf = malloc(ZC_BUFFER_SZ);
        main_arg_list->write_arg_array[i].request_id = ZC_FREE_ID;
    }
    // allocate xxx arg buffers

    //allocate memory pools
    init_mem_pools();

    //send main_arg_list and memory pools handle to the enclave
    ecall_init_arg_buffers(global_eid, (void *)main_arg_list, (void *)pools);
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

static void free_mem_pool()
{
}

static void create_zc_worker_threads(int numWorkers)
{
}