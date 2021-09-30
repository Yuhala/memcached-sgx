/*
 * Created on Tue Sep 28 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#include "Enclave.h"

#include "zc_args.h"
#include "zc_queues_in.h"

extern zc_resp_q *resp_queue;
extern zc_req_q *req_queue;

zc_arg_list *main_arg_list;
/**
 * initialize request and response queues inside the enclave
 */
void ecall_init_queues_inside(void *req_q, void *resp_q)
{
    printf("-------------in ecall init queues inside ----------------\n");
    req_queue = (zc_req_q *)req_q;
    resp_queue = (zc_resp_q *)resp_q;

    //init locks
    init_zc_queue_locks();
}

void ecall_init_arg_buffers(void *arg_buffers)
{
    main_arg_list = (zc_arg_list *)arg_buffers;
}

void do_zc_switchless_request(zc_req request)
{
}

void get_zc_switchless_response(unsigned int req_id)
{
}

/**
 * Get a free argument slot for a switchless request 
 * for the corresponding routine.
 * Traversing the array each time may not be efficient
 * Could we allocate untrusted memory efficiently from the enclave ? I doubt this would be good
 * because we will end up doing an ocall while trying to prevent an ocall :( ..robbing peter to pay paul
 */
void *get_free_arg_slot(zc_routine func)
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
}