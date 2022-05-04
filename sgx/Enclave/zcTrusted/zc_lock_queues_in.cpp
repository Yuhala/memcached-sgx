/*
 * Created on Wed Sep 29 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * Request and response queue implementations enclave side. It is more or less the same thing
 * in the non-enclave side.
 *
 */

#include "Enclave.h"
#include "zc_types.h"

#include <stdlib.h>

#include "zc_logger_in.h"
#include "zc_queues_in.h"

#include "memcached/mpool.h"

#include "zc_mem.h"

/**
 * linked list/queue with zc switchless requests and responses
 * future work: try lock free
 */
zc_queue *resp_queue = NULL;
zc_queue *req_queue = NULL;

// locks used by enclave code to synchronize insertion and removal in queues.
sgx_thread_mutex_t req_q_lock;  // = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t resp_q_lock; // = SGX_THREAD_MUTEX_INITIALIZER;

sgx_thread_mutex_t pool_index_lock;

/**
 * Init pools lock. A memory pool is not actually locked but we use a global variable to assign specific pool indices to each thread once.
 * This way each thread uses the memory pool corresponding to its thread local pool index.
 */

static int pool_counter = 0;

thread_local int pool_index = -1;
extern zc_mpool_array *mem_pools;

void ZC_QUEUE_LOCK(zc_q_type qt)
{

    switch (qt)
    {
    case ZC_REQ_Q:
        sgx_thread_mutex_lock(&req_q_lock);
        break;
    case ZC_RESP_Q:
        sgx_thread_mutex_lock(&resp_q_lock);
        break;
    }
}

void ZC_QUEUE_UNLOCK(zc_q_type qt)
{

    switch (qt)
    {
    case ZC_REQ_Q:
        sgx_thread_mutex_unlock(&req_q_lock);
        break;
    case ZC_RESP_Q:
        sgx_thread_mutex_unlock(&resp_q_lock);
        break;
    }
}

void ZC_POOL_LOCK()
{
    sgx_thread_mutex_lock(&pool_index_lock);
}

void ZC_POOL_UNLOCK()
{
    sgx_thread_mutex_unlock(&pool_index_lock);
}

void init_zc_queue_locks()
{
    sgx_thread_mutex_init(&req_q_lock, NULL);
    sgx_thread_mutex_init(&resp_q_lock, NULL);
}

void init_zc_pool_lock()
{
    sgx_thread_mutex_init(&pool_index_lock, NULL);
}

/**
 * pyuhala:Routines to allocate and deallocate memory from
 * preallocated untrusted memory pool.
 */

void *zc_malloc(size_t siz)
{

    if (pool_index < 0)
    {
        /**
         * Pool index has not been provided for this thread yet.
         * If all works well, each thread should enter here only once
         */
        sgx_thread_mutex_lock(&pool_index_lock);
        pool_index = pool_counter;
        pool_counter++;
        sgx_thread_mutex_unlock(&pool_index_lock);
    }

    return (mpool_alloc(siz, mem_pools->memory_pools[pool_index]->pool));
}


/**
 * Add item to request or response queues.
 * For switchless ocalls, enclave will add items to request q,
 * while non-enclave code will add items to response q.
 * For clarity we will repeat the same code for both queue types.
 * All req allocs should be done on preallocated untrusted memory pool, else
 * untrusted code cannot access the info.
 */
void zc_enq(zc_q_type qt, void *info)
{
    zc_queue *queue;

    // check which queue we are working with
    switch (qt)
    {
    case ZC_REQ_Q:
        queue = req_queue;
        break;
    case ZC_RESP_Q:
        queue = resp_queue;
        break;
    }

    if (queue->count < ZC_QUEUE_CAPACITY)
    {
        zc_req_node *req_node = (zc_req_node *)zc_malloc(sizeof(zc_req_node));
        req_node->req = (zc_req *)info;
        req_node->next = NULL; // pyuhala:he just came in so there is no one behind him, yet :)

        ZC_QUEUE_LOCK(qt);
        if (!isempty(qt))
        {

            queue->rear->next = req_node;
            queue->rear = req_node;
        }
        else
        {
            queue->front = queue->rear = req_node;
        }
        queue->count++;
        ZC_QUEUE_UNLOCK(qt);
    }
    else
    {
        // printf("req queue is full");
    }
}

/**
 * get item from request or response queues.
 * For switchless ocalls, enclave will remove items from response q,
 * while non-enclave code will add items to response q. *
 */
void *zc_dq(zc_q_type qt)
{
    void *return_val;
    zc_queue *queue;

    // check which queue we are working with
    switch (qt)
    {
    case ZC_REQ_Q:
        queue = req_queue;
        break;
    case ZC_RESP_Q:
        queue = resp_queue;
        break;
    }

    zc_req_node *tmp_req;
    ZC_QUEUE_LOCK(qt);
    return_val = (void *)queue->front->req;
    tmp_req = queue->front;
    queue->front = queue->front->next;
    queue->count--;
    ZC_QUEUE_UNLOCK(qt);

    // free(tmp_req);

    return return_val;
}

/**
 * checks if request or response queue is empty
 */
int isempty(zc_q_type qt)
{
    int ret = 0;
    switch (qt)
    {
    case ZC_REQ_Q:
        ret = (req_queue->rear == NULL) ? 1 : 0;
        break;
    case ZC_RESP_Q:
        ret = (resp_queue->rear == NULL) ? 1 : 0;
        break;
    }

    return ret;
}

void free_queues()
{
    // TODO: empty queues first
    free(req_queue);
    free(resp_queue);
}