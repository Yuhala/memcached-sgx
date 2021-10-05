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

//#define ZC_LOGGING 1

/**
 * Lock free queues for zc switchless calls
 */
extern struct mpmcq *req_mpmcq;
extern struct mpmcq *resp_mpmcq;

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

/**
 * initialize request and response queues inside the enclave
 */
void ecall_init_mpmc_queues_inside(void *req_q, void *resp_q)
{
    log_zc_routine(__func__);
    req_mpmcq = (struct mpmcq *)req_q;
    resp_mpmcq = (struct mpmcq *)resp_q;

    //initialize zc switchless map
    //use_zc_test();
}

void ecall_init_mem_pools(void *pools)
{
    log_zc_routine(__func__);

    //init pools
    mem_pools = (zc_mpool_array *)pools;
    //zc_malloc_test();

    //init locks
    init_zc_pool_lock();
    sgx_thread_mutex_init(&counter_setter_lock, NULL);

    //active zc
    zc_switchless_active = true;
}

void do_zc_switchless_request(zc_req *req, unsigned int pool_index)
{
    log_zc_routine(__func__);
    //enqueue request on request queue
    //zc_mpmc_enqueue(req_mpmcq, (void *)request);#include <stdlib.h>

    mem_pools->memory_pools[pool_index]->request = req;
    //pyuhala: I don't think atomic store is necessary here.. but lets keep it
    __atomic_store_n(&mem_pools->memory_pools[pool_index]->pool_status, (int)PROCESSING, __ATOMIC_ACQUIRE);
    //mem_pools->memory_pools[pool_index]->pool_status = (int)PROCESSING;

    // wait for response
    ZC_REQUEST_WAIT(&req->is_done);
    /**
     * The worker thread will eventually change the status of the request to done, 
     * and we will leave the waiting loop
     */
}

/**
 * Reserves a switchless worker/memory pool
 * changed this routine abit: i reserve now in get_free_pool 
 * to minimize concurrency issues.. wud make this cleaner
 * later.
 */
int reserve_worker()
{
    //log_zc_routine(__func__);
    if (!zc_switchless_active)
    {
        return ZC_NO_FREE_POOL;
    }

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
 * Releases a switchless worker/memory pool
 */
void release_worker(unsigned int pool_index)
{

    log_zc_routine(__func__);
    //ZC_POOL_LOCK();
    //mem_pools->memory_pools[pool_index]->pool_status = (int)UNUSED;
    __atomic_store_n(&mem_pools->memory_pools[pool_index]->pool_status, (int)UNUSED, __ATOMIC_ACQUIRE);

    //ZC_POOL_UNLOCK();

    //printf("---------------released pool/worker ---------------\n");
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

    for (int i = 0; i < NUM_POOLS; i++)
    {
        //status = mem_pools->memory_pools[i]->pool_status;
        //status = __atomic_load_n(&mem_pools->memory_pools[i]->pool_status, __ATOMIC_RELAXED);

        if (!mem_pools->memory_pools[i]->active)
        {
            continue;
        }
        //if pool status is unused, reserve it.
        bool res = __atomic_compare_exchange_n(&mem_pools->memory_pools[i]->pool_status,
                                               &unused, reserved, false, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE);
        if (res)
        {
            return i;
        }

        //if (mem_pools->memory_pools[i]->active && status == (int)UNUSED)
        //{
        //pyuhala: we may have concurrency issues here..well not really
        //ZC_POOL_LOCK();
        //mem_pools->memory_pools[i]->pool_status = (int)RESERVED;
        //__atomic_store_n(&mem_pools->memory_pools[i]->pool_status, (int)RESERVED, __ATOMIC_RELAXED);
        //mem_pools->memory_pools[i]->curr_user_id = req_num;
        //__atomic_store_n(&mem_pools->memory_pools[i]->curr_user_id, req_num, __ATOMIC_RELAXED);

        //ZC_POOL_UNLOCK();

        //make sure it is you who reserved here,
        //b/c a diff thread could have found this free pool at the same time as you,
        //and you should continue checking for an unused slot

        //if (mem_pools->memory_pools[i]->curr_user_id == req_num)
        //{
        //return i;
        //}
        //continue;
    }
    return ZC_NO_FREE_POOL;
}

/**
 * Each caller thread will wait for the request to be done
 * before progressing. I created a separate function because the 
 * implementation of this "wait" may/would change depending on perfs.
 * For now we use an asm pause to free some CPU time. 
 */
void ZC_REQUEST_WAIT(volatile int *isDone)
{
    log_zc_routine(__func__);
    //spin_lock(isDone);
    while ((*isDone) != ZC_REQUEST_DONE)
    {
        //do nothing
        //ZC_PAUSE();
    }
    //printf("---- request is done ------\n");
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

static inline void asm_pause(void)
{
    __asm__ __volatile__("pause"
                         :
                         :
                         : "memory");
}

#define ZC_LOGGING_IN 1
#undef ZC_LOGGING_IN

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
