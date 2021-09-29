/*
 * Created on Tue Sep 28 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#include "Enclave.h"

#include "zc_args.h"

extern zc_resp_q *resp_queue;
extern zc_req_q *req_queue;

void init_zc_switchless(int val)
{

    printf("I'm in init zc switchless\n");
}

/**
 * initialize request and response queues inside the enclave
 */
void ecall_init_queues_inside(void *req_q, void *resp_q)
{
    printf("-------------in ecall init queues inside ----------------\n");
    req_queue = (zc_req_q *)req_q;
    resp_queue = (zc_resp_q *)resp_q;
}