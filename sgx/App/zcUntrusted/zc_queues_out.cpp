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
zc_req_q *req_queue;
zc_resp_q *resp_queue;



// locks used by non-enclave code to synchronize insertion and gets
pthread_mutex_t req_q_lock;  // = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t resp_q_lock; // = PTHREAD_MUTEX_INITIALIZER;

void REQ_LOCK()
{
    pthread_mutex_lock(&req_q_lock);
}

void REQ_UNLOCK()
{
    pthread_mutex_unlock(&req_q_lock);
}

void RESP_LOCK()
{
    pthread_mutex_lock(&resp_q_lock);
}

void RESP_UNLOCK()
{
    pthread_mutex_unlock(&resp_q_lock);
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
    req_queue = (zc_req_q *)malloc(sizeof(zc_req_q));
    resp_queue = (zc_resp_q *)malloc(sizeof(zc_resp_q));

    //initialize request queue
    req_queue->front = NULL;
    req_queue->rear = NULL;
    req_queue->req_count = 0;

    //initialize response queue
    resp_queue->front = NULL;
    resp_queue->rear = NULL;
    resp_queue->resp_count = 0;

    //init locks
    init_zc_queue_locks();

    //pass these queues to the enclave
    ecall_init_queues_inside(global_eid, (void *)req_queue, (void *)resp_queue);

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