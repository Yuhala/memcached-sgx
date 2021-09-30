/*
 * Created on Wed Sep 29 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * Request and response queue implementations enclave side. It is more or less the same thing
 * in the non-enclave side.
 * 
 */

#include "Enclave.h"
#include "zc_args.h"

#include <stdlib.h>

#include "zc_logger_in.h"
#include "zc_queues_in.h"

/**
 * linked list/queue with zc switchless requests and responses
 * future work: try lock free
 */
zc_resp_q *resp_queue = NULL;
zc_req_q *req_queue = NULL;


// locks used by enclave code to synchronize insertion and removal in queues.
sgx_thread_mutex_t req_q_lock;  // = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t resp_q_lock; // = SGX_THREAD_MUTEX_INITIALIZER;

void REQ_LOCK()
{
    sgx_thread_mutex_lock(&req_q_lock);
}

void REQ_UNLOCK()
{
    sgx_thread_mutex_unlock(&req_q_lock);
}

void RESP_LOCK()
{
    sgx_thread_mutex_lock(&resp_q_lock);
}

void RESP_UNLOCK()
{
    sgx_thread_mutex_unlock(&resp_q_lock);
}

void init_zc_queue_locks()
{
    sgx_thread_mutex_init(&req_q_lock, NULL);
    sgx_thread_mutex_init(&resp_q_lock, NULL);
}

/**
 * Add item to request or response queues.
 * For switchless ocalls, enclave will add items to request q,
 * while non-enclave code will add items to response q.
 * For clarity we will repeat the same code for both queue types.
 */
void zc_enq(zc_q_type qt, void *info)
{
    switch (qt)
    {
    case ZC_REQ_Q:
        if (req_queue->req_count < ZC_QUEUE_CAPACITY)
        {
            zc_req_node *req_node = (zc_req_node *)malloc(sizeof(zc_req_node));
            req_node->req = (zc_req *)info;
            req_node->next = NULL; // pyuhala:he just came in so there is no one behind him, yet :)

            REQ_LOCK();
            if (!isempty(ZC_REQ_Q))
            {

                req_queue->rear->next = req_node;
                req_queue->rear = req_node;
            }
            else
            {
                req_queue->front = req_queue->rear = req_node;
            }
            req_queue->req_count++;
            REQ_UNLOCK();
        }
        else
        {
            //printf("req queue is full");
        }

        break;
    case ZC_RESP_Q:
        if (resp_queue->resp_count < ZC_QUEUE_CAPACITY)
        {
            zc_resp_node *resp_node = (zc_resp_node *)malloc(sizeof(zc_resp_node));
            resp_node->resp = (zc_resp *)info;
            resp_node->next = NULL; // pyuhala:he just came in so there is no one behind him, yet :)

            RESP_LOCK();
            if (!isempty(ZC_RESP_Q))
            {

                resp_queue->rear->next = resp_node;
                resp_queue->rear = resp_node;
            }
            else
            {
                resp_queue->front = resp_queue->rear = resp_node;
            }
            resp_queue->resp_count++;
            RESP_UNLOCK();
        }
        else
        {
            //printf("req queue is full");
        }

        break;
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
    switch (qt)
    {
    case ZC_REQ_Q:
        zc_req_node *tmp_req;
        REQ_LOCK();
        return_val = (void *)req_queue->front->req;
        tmp_req = req_queue->front;
        req_queue->front = req_queue->front->next;
        req_queue->req_count--;
        REQ_UNLOCK();

        free(tmp_req);

        break;
    case ZC_RESP_Q:
        zc_resp_node *tmp_resp;
        REQ_LOCK();
        return_val = (void *)resp_queue->front->resp;
        tmp_resp = resp_queue->front;
        resp_queue->front = resp_queue->front->next;
        resp_queue->resp_count--;
        REQ_UNLOCK();

        free(tmp_resp);
        break;
    }

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