/*
 * Created on Wed Sep 29 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * 
 * Request and response FIFO lock-free queues for switchless requests
 * Revision on C queues: https://www.codesdope.com/blog/article/making-a-queue-using-linked-list-in-c/
 * 
 */

#include "Enclave_u.h"
#include "sgx_urts.h"

#include <stdlib.h>
#include <pthread.h>

#include "zc_logger.h"
#include "zc_queues_out.h"

//pyuhala:some useful global variables
extern sgx_enclave_id_t global_eid;

/**
 * linked list/queue with zc switchless requests and responses
 * future work: try lock free
 */
zc_queue *req_queue;
zc_queue *resp_queue;

// locks used by non-enclave code to synchronize insertion and gets
pthread_mutex_t req_q_lock;  // = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t resp_q_lock; // = PTHREAD_MUTEX_INITIALIZER;

void ZC_QUEUE_LOCK(zc_q_type qt)
{

    switch (qt)
    {
    case ZC_REQ_Q:
        pthread_mutex_lock(&req_q_lock);
        break;
    case ZC_RESP_Q:
        pthread_mutex_lock(&resp_q_lock);
        break;
    }
}

void ZC_QUEUE_UNLOCK(zc_q_type qt)
{

    switch (qt)
    {
    case ZC_REQ_Q:
        pthread_mutex_unlock(&req_q_lock);
        break;
    case ZC_RESP_Q:
        pthread_mutex_unlock(&resp_q_lock);
        break;
    }
}

void init_zc_queue_locks()
{
    pthread_mutex_init(&req_q_lock, NULL);
    pthread_mutex_init(&resp_q_lock, NULL);
}

/**
 * Initialize request and response queues
 */

void init_zc_queues()
{
    log_zc_routine(__func__);

    //allocate memory for queues
    req_queue = (zc_queue *)malloc(sizeof(zc_queue));
    resp_queue = (zc_queue *)malloc(sizeof(zc_queue));
    ;

    //initialize request queue
    req_queue->front = NULL;
    req_queue->rear = NULL;
    req_queue->count = 0;

    //initialize response queue
    resp_queue->front = NULL;
    resp_queue->rear = NULL;
    resp_queue->count = 0;

    //init locks
    init_zc_queue_locks();

    //pass these queues to the enclave
    //ecall_init_lock_queues_inside(global_eid, (void *)req_queue, (void *)resp_queue);

    //test
    if (isempty(ZC_REQ_Q))
    {
        printf("zc request queue is empty >>>>>>>>>>>>>>>>\n");
    }
}

/**
 * Add item to request or response queues.
 * For switchless ocalls, enclave will add items to request q,
 * while non-enclave code will add items to response q.
 * For clarity we will repeat the same code for both queue types.
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
        zc_req_node *req_node = (zc_req_node *)malloc(sizeof(zc_req_node));
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
        //printf("req queue is full");
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

    free(tmp_req);

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
    //TODO: empty queues first
    free(req_queue);
    free(resp_queue);
}

/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

//#include <sgx_spinlock.h>

static inline void _mm_pause(void) __attribute__((always_inline));
static inline int _InterlockedExchange(int volatile * dst, int val) __attribute__((always_inline));

static inline void _mm_pause(void)  /* definition requires -ffreestanding */
{
    __asm __volatile(
        "pause"
    );
}

static inline int _InterlockedExchange(int volatile * dst, int val)
{
    int res;

    __asm __volatile(
        "lock xchg %2, %1;"
        "mov %2, %0"
        : "=m" (res)
        : "m" (*dst),
        "r" (val) 
        : "memory"
    );

    return (res);
   
}

uint32_t zc_spin_lock(volatile int *lock)
{
    while(_InterlockedExchange((volatile int *)lock, 1) != 0) {
        while (*lock) {
            /* tell cpu we are spinning */
            _mm_pause();
        } 
    }

    return (0);
}

uint32_t zc_spin_unlock(volatile int *lock)
{
    *lock = 0;

    return (0);
}