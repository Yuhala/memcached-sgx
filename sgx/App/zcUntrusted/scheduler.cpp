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
unsigned long int total_sl = 0; /* total # of switchless calls at runtime */
unsigned long int total_fb = 0; /* total # of fallback calls */

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

extern bool use_zc_scheduler;

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
//caculates optimum # workers for the next scheduling phase
static int get_optimum_workers(vector<unsigned long long int> &wasted_cycles, vector<double> &sl_ratios, int num_micro_q);

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

    //use_zc_scheduler = false;

    //Test workers w/o scheduler: set to true if you don't want any scheduling
    if (!use_zc_scheduler)
    {
        set_num_workers(optimum_workers);
        return NULL;
    }

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

    static int count = 0;
    set_num_workers(desired_workers);
    count++;
    if (count % COUNTER == 0)
    {
        printf("doing scheduling: nThreads = %d >>>>>>>>>\n", desired_workers);
    }
}
/**
 * find best configuration/ie optimum number of workers for 
 * the next scheduling phase.
 */
static void do_configuration()
{
    static unsigned int counter = 0;

    //printf("doing configuration >>>>>>>>>>>>>\n");
    /**
     * micro quantums will vary as follows: 0, 1, 3, ... , num_workers
     */
    int num_micro_q = num_workers + 1;
    // list of Uis (ie wasted cpu cycles) for micro quantums.
    vector<unsigned long long int> wasted_cycles(num_micro_q);

    // list of sl_ratios
    vector<double> sl_ratios(num_micro_q);

    // number of wasted cycles for a micro quantum
    unsigned long long int wasted_cycles_mq;

    // number of fallbacks for this micro quantum
    unsigned int num_fb_mq = 0;

    // number of switchless calls for this micro quantum
    unsigned int num_sl_mq = 0;

    // index for micro quantum
    int micro_q_index = 0;

    // ratio of sl to fb calls for micro quantum
    double sl_ratio_mq = 0.0;

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
        //num_fb_mq = zc_statistics->num_zc_fallback_calls;
        num_fb_mq = __atomic_load_n(&zc_statistics->num_zc_fallback_calls, __ATOMIC_RELAXED);

        // get num of fallback calls for this micro quantum
        //num_sl_mq = zc_statistics->num_zc_swtless_calls;
        num_sl_mq = __atomic_load_n(&zc_statistics->num_zc_swtless_calls, __ATOMIC_RELAXED);

        // calculate wasted cycles for this micro quantum: Ui = F.Tes + i.u.Q.cpu_freq
        wasted_cycles_mq = (num_fb_mq * TIME_ENCLAVE_SWITCH) + (micro_q_index * MICRO_QUANTUM * cpu_freq * MEGA);

        // calculate sl ratio
        if (num_fb_mq == 0)
        {
            sl_ratio_mq = (double)num_sl_mq / SMALL_NUM;
        }
        else
        {
            sl_ratio_mq = (double)num_sl_mq / num_fb_mq;
        }

        // add ratio to vector
        sl_ratios[micro_q_index] = sl_ratio_mq;

        // add Ui to vector
        wasted_cycles[micro_q_index] = wasted_cycles_mq;

        // print config every 100 calls
        if (counter % COUNTER == 0 && false)
        {
            printf("config nThreads: %d num sl calls: %d num fb calls: %d wasted cycles: %lld sl_ratio: %f >>>>>>>>>>>>>>>\n",
                   micro_q_index, num_sl_mq, num_fb_mq, wasted_cycles_mq, sl_ratio_mq);
        }
        micro_q_index++;
    }

    // compute optimum number of workers
    optimum_workers = get_optimum_workers(wasted_cycles, sl_ratios, num_micro_q);

    counter++;
}

/**
 * Function to get the optimum number
 * of workers for our scheduling policy.
 * pyuhala: my new policy -- opt workers = workers with highest sl/fb ratio
 */
static int get_optimum_workers(vector<unsigned long long int> &wasted_cycles, vector<double> &sl_ratios, int num_micro_q)
{
    int ret_index = 0;

    /* policy used for getting optimum workers */
    typedef enum
    {
        WASTED_CYCLES,
        SL_FB_RATIO
    } optimum_worker_policy;

    optimum_worker_policy policy = WASTED_CYCLES;

    switch (policy)
    {
    case WASTED_CYCLES:
    {
        // policy 1: get # workers corresponding to min wasted cycles
        int min_index = 0;
        for (int i = 0; i < num_micro_q; i++)
        {
            //pyuhala: my observation: the min almost always (or always!) corresponds to i = 0
            //TODO: change to < (just testing to see what > gets)
            if (wasted_cycles[i] < wasted_cycles[min_index])
            {
                min_index = i;
            }
        }
        ret_index = min_index;
    }
    break;
    case SL_FB_RATIO:
    {
        // policy 2: get # workers corresponding to max sl/fb ratio
        int max_index = 0;
        for (int j = 0; j < num_micro_q; j++)
        {

            if (sl_ratios[j] > sl_ratios[max_index])
            {
                max_index = j;
            }
        }
        ret_index = max_index;
    }
    break;

    default:
        ret_index = num_workers;
        break;
    }

    return ret_index;
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
    int unused = (int)UNUSED;

    int status = __atomic_load_n(&pools->memory_pools[index]->pool_status, __ATOMIC_RELAXED);
    int active = __atomic_load_n(&pools->memory_pools[index]->active, __ATOMIC_RELAXED);
    int to_be_paused = __atomic_load_n(&pools->memory_pools[index]->scheduler_pause, __ATOMIC_RELAXED);

    bool test = (active == 1) && (status != paused && (to_be_paused != 1));
    if (test)
    {
        // Worker is already active and not scheduled to pause, return.
        return;
    }

    /**
     * Activate worker if it is paused. The worker may not be already 
     * sleeping/paused but it cannot be treating a request at this point.
     */
    if (status == paused)
    {
        pthread_kill(workers[index], SIGUSR1);
    }
}
/**
 * Sets pause field in corresponding buffer.
 * The worker will pause once it sees this value is set.
 * 
 */
static void deactivate_worker(int index)
{
    __atomic_store_n(&pools->memory_pools[index]->scheduler_pause, 1, __ATOMIC_SEQ_CST);
}

//reinitize statistics
void reinitialize_stats()
{
    //pthread_mutex_lock(&stats_lock);
    //update global totals b4 zeroing
    total_sl += __atomic_load_n(&zc_statistics->num_zc_swtless_calls, __ATOMIC_RELAXED);
    total_fb += __atomic_load_n(&zc_statistics->num_zc_fallback_calls, __ATOMIC_RELAXED);

    __atomic_store_n(&zc_statistics->num_zc_fallback_calls, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&zc_statistics->num_zc_swtless_calls, 0, __ATOMIC_SEQ_CST);

    //pthread_mutex_unlock(&stats_lock);
}
