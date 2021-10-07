/*
 * Created on Tue Sep 28 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * Builtins doc: https://gcc.gnu.org/onlinedocs/gcc/_005f_005fatomic-Builtins.html
 */

#include "Enclave.h"

#include "zc_types.h"
#include "zc_queues_in.h"
#include "memcached/mpool.h"
#include "zc_in.h"
#include "zc_lfu.h"
#include "zc_spinlocks.h"

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

#include "zc_mpmc_queue.h"

//#define ZC_LOGGING 1

/**
 * Lock free queues for zc switchless calls
 */
extern struct mpmcq *req_mpmcq;
extern struct mpmcq *resp_mpmcq;
static bool use_queues = false;

zc_mpool_array *mem_pools;

//zc_arg_list *main_arg_list;

//forward declarations
void zc_malloc_test();
static inline void asm_pause(void);
static unsigned int get_counter();

//track enclave threads
static int enclave_request_counter = 0;
//thread_local int enclave_thread_id = -1;
sgx_thread_mutex_t counter_setter_lock;
bool zc_switchless_active = false;

zc_stats *switchless_stats;

/**
 * initialize request and response queues inside the enclave
 */
void ecall_init_mpmc_queues_inside(void *req_q, void *resp_q)
{
    log_zc_routine(__func__);
    req_mpmcq = (struct mpmcq *)req_q;
    resp_mpmcq = (struct mpmcq *)resp_q;
    use_queues = true;

    //initialize zc switchless map
    //use_zc_test();
}

void ecall_init_mem_pools(void *pools, void *statistics)
{
    log_zc_routine(__func__);

    //init pools
    mem_pools = (zc_mpool_array *)pools;
    //zc_malloc_test();

    //set address of num fallback requests
    switchless_stats = (zc_stats *)statistics;

    //init locks
    init_zc_pool_lock();
    sgx_thread_mutex_init(&counter_setter_lock, NULL);

    //active zc
    zc_switchless_active = true;
}

/**
 * Reserves a switchless worker/memory pool
 * changed this routine abit: i reserve now in get_free_pool 
 * to minimize concurrency issues.. wud make this cleaner
 * later.
 */
int reserve_worker()
{

    if (!zc_switchless_active)
    {
        return ZC_NO_FREE_POOL;
    }

    //log_zc_routine(__func__);
    int index = get_free_pool();
    if (index == ZC_NO_FREE_POOL)
    {
        /* there is no free worker..hence pool, do regular ocall */
        return ZC_NO_FREE_POOL;
    }
    else
    {
        //* reserve the worker/pool */
        //mem_pools->memory_pools[index]->pool_status = (int)RESERVED;
        return index;
    }
}

/**
 * get an unused memory pool which is active
 */
int get_free_pool()
{
    //log_zc_routine(__func__);
    //int free_pool_index = ZC_NO_FREE_POOL;

    int status;
    // get a thread identifier first
    //int req_num = get_counter();

    int unused = (int)UNUSED;
    int reserved = (int)RESERVED;
    bool res = false;

    for (int i = 0; i < NUM_POOLS; i++)
    {
        //status = mem_pools->memory_pools[i]->pool_status;
        //status = __atomic_load_n(&mem_pools->memory_pools[i]->pool_status, __ATOMIC_RELAXED);

        if (!mem_pools->memory_pools[i]->active)
        {
            continue;
        }
        //if pool status is unused, reserve it.
        /**
         * pyuhala: i used release memory order here in the caller and acquire in the 
         * worker outside so the latter sees the changes
         */

        if (mem_pools->memory_pools[i]->pool_status == unused)
        {
            // lock, test again, and change status
            spin_lock(&mem_pools->memory_pools[i]->pool_lock);

            res = __atomic_compare_exchange_n(&mem_pools->memory_pools[i]->pool_status,
                                              &unused, reserved, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);

            spin_unlock(&mem_pools->memory_pools[i]->pool_lock);
        }

        if (res)
        {
            // this call will be switchless; increment num zc switchless
            __atomic_fetch_add(&switchless_stats->num_zc_swtless_calls, 1, __ATOMIC_RELAXED);
            return i;
        }
    }

    //this call will fallback; increment number of fallbacks

    __atomic_fetch_add(&switchless_stats->num_zc_fallback_calls, 1, __ATOMIC_RELAXED);

    return ZC_NO_FREE_POOL;
}

void do_zc_switchless_request(zc_req *req, unsigned int pool_index)
{
    log_zc_routine(__func__);

    if (use_queues)
    {
        //enqueue request on request queue

        int ret = mpmc_enqueue(req_mpmcq, (void *)req);
        if (ret == 1)
        {
            //printf("--------------- caller successfully enqueued request -----------------\n");
        }
    }
    else
    {
        //use worker thread buffers for request

        mem_pools->memory_pools[pool_index]->request = req;
        //pyuhala: I don't think atomic store is necessary here.. but lets keep it
        __atomic_store_n(&mem_pools->memory_pools[pool_index]->pool_status, (int)PROCESSING, __ATOMIC_SEQ_CST);

        //mem_pools->memory_pools[pool_index]->pool_status = (int)PROCESSING;
    }

    // wait for response
    /**
     * The worker thread will eventually change the status of the request to done, 
     * and we will leave the waiting loop
     */
    ZC_REQUEST_WAIT(req);
}

/**
 * Each caller thread will wait for the request to be done
 * before progressing. I created a separate function because the 
 * implementation of this "wait" may/would change depending on perfs.
 * For now we could use an asm pause to free some CPU time. 
 */
void ZC_REQUEST_WAIT(zc_req *request)
{
    log_zc_routine(__func__);
    volatile int done;

    /**
     * pyuhala: using spinlock
     */
    // worker thread will unlock, will wait until it does
    spin_lock(&request->is_done);

    /**
     * pyuhala: w/o atomics
     */

    /* while (*isDone != ZC_REQUEST_DONE)
    {
        //ZC_PAUSE();
    }*/

    /**
     * pyuhala: with atomics
     */

    /* while (__atomic_load_n(isDone, __ATOMIC_SEQ_CST) != ZC_REQUEST_DONE)
    {
       ZC_PAUSE();
    }
    */
    //ZC_ASSERT(*isDone == ZC_REQUEST_DONE);
}

/**
 * get a temporary counter/id value for the request
 */
static unsigned int get_counter()
{
    //log_zc_routine(__func__);

    //sgx_thread_mutex_lock(&counter_setter_lock);
    int val = __atomic_fetch_add(&enclave_request_counter, 1, __ATOMIC_RELAXED);
    //val = enclave_request_counter;
    //enclave_request_counter++;
    //sgx_thread_mutex_unlock(&counter_setter_lock);
    return val;
}

/**
 * Releases a switchless worker/memory pool
 */
void release_worker(unsigned int pool_index)
{
    volatile void *null_req = 0;
    //log_zc_routine(__func__);
    //ZC_POOL_LOCK();
    //mem_pools->memory_pools[pool_index]->pool_status = (int)UNUSED;
    /**
     * pyuhala: remove request from threads pool/buffer
     * 
     * TODO: we should free this memory at some point. For now the memory pool is used and only freed at the end of the program
     */

    mem_pools->memory_pools[pool_index]->request = NULL;

    /**
     * changed status of buffer to unused
     */

    __atomic_store_n(&mem_pools->memory_pools[pool_index]->pool_status, (int)UNUSED, __ATOMIC_SEQ_CST);

    //ZC_POOL_UNLOCK();

    //printf("---------------released pool/worker ---------------\n");
}
static inline void asm_pause(void)
{
    __asm__ __volatile__("pause"
                         :
                         :
                         : "memory");
}

//#define ZC_LOGGING_IN 1

void log_zc_routine(const char *func)
{
#ifdef ZC_LOGGING
    printf("ZC trusted function: %s\n", func);
#else
//do nothing
#endif
}

// -------------------- Test routines -----------------------------
void zc_malloc_test()
{
    printf("-------------- testing array allocation from mem pool------------------\n");
    /*  int *test_int = (int *)zc_malloc(10 * sizeof(int));
    printf("-----zc malloc worked ----------\n");
    for (int i = 0; i < 10; i++)
    {
        test_int[i] = i;
        printf("---- array[%d] = %d ----\n", i, test_int[i]);
    } */

    int *test_int = (int *)zc_malloc(0, 10 * sizeof(int));
    printf("-----zc malloc worked ----------\n");
    for (int i = 0; i < 10; i++)
    {
        test_int[i] = i;
        printf("---- array[%d] = %d ----\n", i, test_int[i]);
    }
}
