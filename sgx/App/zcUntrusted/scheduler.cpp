/*
 * Created on Mon Oct 25 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#include "scheduler.h"
#include <time.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <pthread.h>
#include <signal.h>

#include <errno.h>
#include "zc_logger.h"

//#include "zc_out.h"
#include "zc_types.h"
#include "memcached/mpool.h"
#include "zc_ocalls_out.h"

#include "zc_locks.h"

#include <unistd.h>
#include <sys/syscall.h>

#include <sys/time.h>
#include <string.h>

#include <vector>
using namespace std;

// global variables
int total_sl = 0; /* total # of switchless calls at runtime */
int total_fb = 0; /* total # of fallback calls */

pthread_mutex_t stats_lock;

extern int num_cores;

// cpu frequency in MHz
extern int cpu_freq;

// statistics of the switchless run
extern zc_stats *zc_statistics;

// worker thread array
extern pthread_t *workers;

// memory pool array
extern zc_mpool_array *pools;

// number of initial workers created
extern unsigned int num_workers;

// int optimum workers
int optimum_workers;

pthread_t scheduling_thread;

//forward declarations

static void set_num_workers(int desired_workers);

//scheduling phase
static void do_scheduling(int desired_workers);
//configuration phase
static void do_configuration();
//activate the corresponding worker + buffer/pool
static void activate_worker(int index);
//deactivate the corresponding worker + buffer/pool
static void deactivate_worker(int index);
//scheduling thread routine
void *scheduling_thread_func(void *arg);

/* function definitions */

void init_zc_scheduler()
{
    //pthread_mutex_init(&stats_lock, NULL);
    zc_create_scheduling_thread();
}

void zc_create_scheduling_thread()
{
    /* Creating the scheduling thread */
    printf("Creating zc scheduler thread >>>>>>>>>>>>>\n");
    int pthread_ret = pthread_create(&scheduling_thread, 0, scheduling_thread_func, NULL);
    if (pthread_ret != 0)
    {
        fprintf(stderr, "Error: scheduling thread initialization failed\n");
        exit(1);
    }
}

/**
 * Scheduler function: scheduler simply changes state as follows:
 * SCHED PHASE --> CONFIG PHASE --> SCHED PHASE --> ... --> EXIT
 */
void *scheduling_thread_func(void *arg)
{
    //start scheduler with optimum workers = num workers
    optimum_workers = num_workers;
    //scheduler loop
    for (;;)
    {
        //initialize scheduler in a scheduling phase
        do_scheduling(optimum_workers);
        sleep(QUANTUM);
        //sleep(1);

        //configure optimum workers for next scheduling phase
        do_configuration();
    }
}

/**
 * schedule/activate num_workers worker threads for the
 * scheduling phase
 */
static void do_scheduling(int desired_workers)
{
    printf("doing scheduling: nThreads = %d >>>>>>>>>\n", desired_workers);
    static int count = 0;
    set_num_workers(desired_workers);
    count++;
    if (count % 10 == 0)
    {
        //printf("sheduling %d workers >>>> \n", desired_workers);
    }
}
/**
 * find best configuration/ie optimum number of workers for 
 * the next scheduling phase.
 */
static void do_configuration()
{
    printf("doing configuration >>>>>>>>>>>>>\n");
    /**
     * micro quantums will vary as follows: 0, 1, 3, ... , num_workers
     */
    int num_micro_q = num_workers + 1;
    // list of Uis (ie wasted cpu cycles) for micro quantums.
    vector<unsigned long long int> zcU(num_micro_q);
    // number of wasted cycles for a micro quantum
    unsigned long long int wasted_cycles_mq;

    // number of fallbacks for this micro quantum
    unsigned int num_fb_mq = 0;

    // number of switchless calls for this micro quantum
    unsigned int num_sl_mq = 0;

    // index for micro quantum
    int micro_q_index = 0;

    // vary the number of active workers for the different micro quanta
    while (micro_q_index < num_micro_q)
    {
        // reintialize statistics for this micro quantum
        reinitialize_stats();

        // set number of workers for quantum
        set_num_workers(micro_q_index);
        // sleep for micro quantum time
        sleep(MICRO_QUANTUM);

        // get num of fallback calls for this micro quantum
        num_fb_mq = zc_statistics->num_zc_fallback_calls;

        // get num of fallback calls for this micro quantum
        num_sl_mq = zc_statistics->num_zc_swtless_calls;

        // calculate wasted cycles for this micro quantum: Ui = F.Tes + i.u.Q.cpu_freq
        wasted_cycles_mq = (num_fb_mq * TIME_ENCLAVE_SWITCH) + (micro_q_index * MICRO_QUANTUM * cpu_freq * MEGA);

        // add Ui to vector
        zcU[micro_q_index] = wasted_cycles_mq;
        printf("config nThreads: %d num num sl calls: %d num fb calls: %d wasted cycles: %lld >>>>>>>>>>>>>>>\n",
               micro_q_index, num_sl_mq, num_fb_mq, wasted_cycles_mq);
        micro_q_index++;
    }

    // compute num_workers that minimizes Ui for this configuration phase
    unsigned long long int min_index = 0;
    for (int i = 0; i < num_micro_q; i++)
    {
        //TODO: change to <
        //pyuhala: should be < (i'm testing stuff ...)
        if (zcU[i] > zcU[min_index])
        {
            min_index = i;
        }
    }

    optimum_workers = min_index;
}

/**
 * Set number of active workers + pools. We activate workers: 0 .. desired_workers 
 * and deactivate all the rest.
 */
static void set_num_workers(int desired_workers)
{
    int num = desired_workers;
    if (desired_workers > num_workers)
    {
        /**
         * This should never happen, but who knows :)
         */
        num = num_workers;
    }

    for (int i = 0; i < num; i++)
    {
        activate_worker(i);
    }
    for (int j = num; j < num_workers; j++)
    {
        deactivate_worker(j);
    }
}

/**
 * Activates the corresponding worker + buffer/pool
 * by setting the pool state to UNUSED if it is PAUSED.
 */
static void activate_worker(int index)

{

    // buffer state
    int paused = (int)PAUSED;
    int micro_paused = (int)MICRO_PAUSED;
    int unused = (int)UNUSED;

    // if worker is already active and not scheduled to pause, return.
    int status = __atomic_load_n(&pools->memory_pools[index]->pool_status, __ATOMIC_SEQ_CST);
    int to_be_paused = __atomic_load_n(&pools->memory_pools[index]->scheduler_pause, __ATOMIC_SEQ_CST);
    bool test = (pools->memory_pools[index]->active == 1) && (status != (int)PAUSED) && (to_be_paused != 1);
    if (test)
    {
        return;
    }

    // activate buffer
    bool res = __atomic_compare_exchange_n(&pools->memory_pools[index]->pool_status,
                                           &paused, unused, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);

    // activate/wake paused worker
    if (res)
    {
        /**
         * We should be here only if worker is actually paused
         */
        //pools->memory_pools[index]->active = 1;
        //pools->memory_pools[index]->scheduler_pause = 0;

        pthread_kill(workers[index], SIGUSR1);
    }
}
/**
 * Deactivates the corresponding worker + buffer/pool
 * by setting the pool state to PAUSED. The worker thread 
 * will eventually sleep after it sees its state is PAUSED.
 * 
 */
static void deactivate_worker(int index)
{

    int status = __atomic_load_n(&pools->memory_pools[index]->pool_status, __ATOMIC_SEQ_CST);

    if (status == (int)PROCESSING || status == (int)RESERVED)
    {
        /**
         * we check for pool state RESERVED/PR0CESSING to prevent a situation where we deactivate a worker/buffer 
         * just after it has been reserved by caller. This will lead to us "probably" (may not happen) pausing
         * a worker/buffer with a pending request b4 it treats it. In such a case we need to safely tell the 
         * worker to pause after treating the request.
         */
        pools->memory_pools[index]->scheduler_pause = 1;
    }
    else
    {
        //deactivate buffer
        __atomic_store_n(&pools->memory_pools[index]->pool_status, int(PAUSED), __ATOMIC_SEQ_CST);
        pools->memory_pools[index]->active = 0;
        //printf("scheduler deactivated pool %d >>>>>>>>>>> \n", index);
        //at some point worker will pause after seeing buffer state = PAUSED
    }
}

//reinitize statistics
void reinitialize_stats()
{
    //pthread_mutex_lock(&stats_lock);
    __atomic_store_n(&zc_statistics->num_zc_fallback_calls, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&zc_statistics->num_zc_swtless_calls, 0, __ATOMIC_SEQ_CST);

    //pthread_mutex_unlock(&stats_lock);
}
