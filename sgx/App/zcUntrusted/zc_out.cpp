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

/**
 * Argument list for different libc routines/ocalls. This list/struct will have an entry for 
 * each switchless ocall routine. 
 * The size of each argument array will depend on the number of 
 * worker threads.
 */

struct zc_arg_list
{
    fread_arg_zc *fread_arg_array;
    fwrite_arg_zc *fwrite_arg_array;
    read_arg_zc *read_arg_array;
    write_arg_zc *write_arg_array;
};

//pyuhala:some useful global variables
extern sgx_enclave_id_t global_eid;

//pyuhala:forward declarations
static void worker_loop(void);
static int getOptimalWorkers(int);
static void init_arg_buffers_out(int numWorkers);
void *zc_worker_thread(void *input);

//useful globals
int num_cores = -1;

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
    init_queues();
}

/**
 * Allocates memory for thread-specific argument buffers
 */
static void init_arg_buffers_out(int numWorkers)

{
    log_zc_routine(__func__);
    
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