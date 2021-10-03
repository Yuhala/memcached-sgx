/*
 * Created on Tue Sep 28 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#include "Enclave.h"

#include "zc_types.h"
#include "zc_queues_in.h"
#include "memcached/mpool.h"
#include "zc_in.h"
#include "zc_lfu.h"

/**
 * Lock free queues for zc switchless calls
 */
extern struct mpmcq *req_mpmcq;
extern struct mpmcq *resp_mpmcq;

zc_mpool *mem_pools;

//zc_arg_list *main_arg_list;

//forward declarations
void zc_malloc_test();
static inline void asm_pause(void);

/**
 * initialize request and response queues inside the enclave
 */
void ecall_init_mpmc_queues_inside(void *req_q, void *resp_q)
{
    printf("-------------in ecall init queues inside ----------------\n");
    req_mpmcq = (struct mpmcq *)req_q;
    resp_mpmcq = (struct mpmcq *)resp_q;

    //init locks
    init_zc_pool_lock();
    //initialize zc switchless map
    //use_zc_test();
}

void ecall_init_mem_pools(void *pools)
{
    printf("------------- in ecall init mem pools ----------------\n");

    //init pools
    mem_pools = (zc_mpool *)pools;
    //zc_malloc_test();
}

void do_zc_switchless_request(zc_req *request)
{
    //enqueue request on request queue
    zc_mpmc_enqueue(req_mpmcq, (void *)request);
    //set a flag to notify workers ??
}

void get_zc_switchless_response(unsigned int req_id)
{
    // not sure if this routine is useful
}

/**
 * Each caller thread will wait for the request to be done
 * before progressing. I created a separate function because the 
 * implementation of this "wait" may/would change depending on perfs.
 * For now we use an asm pause to free some CPU time. 
 */
void ZC_REQUEST_WAIT(volatile int *isDone)
{
    while ((*isDone) != ZC_REQUEST_DONE)
    {
        //do nothing
        ZC_PAUSE();
    }
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
    printf("-------------- testing array allocation from mem pool ------------------\n");
    int *test_int = (int *)zc_malloc(10 * sizeof(int));
    printf("-----zc malloc worked ----------\n");
    for (int i = 0; i < 10; i++)
    {
        test_int[i] = i;
        printf("---- array[%d] = %d ----\n", i, test_int[i]);
    }
}

/**
 * Get a free argument slot for a switchless request 
 * for the corresponding routine.
 * Traversing the array each time may not be efficient
 * Could we allocate untrusted memory efficiently from the enclave ? I doubt this would be good
 * because we will end up doing an ocall while trying to prevent an ocall :( ..robbing peter to pay paul
 */

/* void *get_free_arg_slot(zc_routine func)
{
    void *arg_slot == NULL;

    switch (func)
    {
    case ZC_FREAD:
        for (int i = 0; i < ZC_QUEUE_CAPACITY; i++)
        {
            if (main_arg_list->fread_arg_array[i].request_id < 0)
            {
                arg_slot = (void *)fread_arg_array[i];
                break;
            }
        }
        break;
    case ZC_FWRITE:
        for (int i = 0; i < ZC_QUEUE_CAPACITY; i++)
        {
            if (main_arg_list->fwrite_arg_array[i].request_id < 0)
            {
                arg_slot = (void *)fwrite_arg_array[i];
                break;
            }
        }
        break;
    case ZC_READ:
        for (int i = 0; i < ZC_QUEUE_CAPACITY; i++)
        {
            if (main_arg_list->read_arg_array[i].request_id < 0)
            {
                arg_slot = (void *)read_arg_array[i];
                break;
            }
        }
        break;
    case ZC_WRITE:
        for (int i = 0; i < ZC_QUEUE_CAPACITY; i++)
        {
            if (main_arg_list->write_arg_array[i].request_id < 0)
            {
                arg_slot = (void *)write_arg_array[i];
                break;
            }
        }
        break;
    }

    return arg_slot;
}*/
