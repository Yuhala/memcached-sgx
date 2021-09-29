/*
 * Created on Wed Sep 29 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * 
 * Request and response FIFO queues for switchless requests
 * Revision: https://www.codesdope.com/blog/article/making-a-queue-using-linked-list-in-c/
 */

#include "Enclave_u.h"
#include "sgx_urts.h"

#include <stdlib.h>

#include "zc_args.h"
#include "zc_logger.h"

//pyuhala:some useful global variables
extern sgx_enclave_id_t global_eid;

zc_resp_q *resp_queue;
zc_req_q *req_queue;

/**
 * Initialize request and response queues
 */

void init_queues()
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

    //pass these queues to the enclave
    ecall_init_queues_inside(global_eid, (void *)req_queue, (void *)resp_queue);
}

void free_queues()
{
    //TODO: empty queues first
    free(req_queue);
    free(resp_queue);
}