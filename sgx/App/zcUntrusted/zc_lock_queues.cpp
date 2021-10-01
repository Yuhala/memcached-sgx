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