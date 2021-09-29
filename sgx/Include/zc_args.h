/*
 * Created on Wed Sep 29 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * 
 * For the proof of concept I implement specific structures which will hold the 
 * arguments of each switchless function. We will allocate "enough" memory at the onset to avoid ocalls to resize.
 * Future work can implement a more generic system.
 * ZC == zero config (as in zero config/dynamic switchless call system)
 */

#ifndef ZC_ARGS_H
#define ZC_ARGS_H

#include <sys/types.h>
#include "struct/sgx_stdio_struct.h"

#define ZC_BUFFER_SZ 1024 * 1024 /* 1mb default buffer size should be enough for static buffers */

/**
 * structure containing pointers to argument buffers. 
 * These structures will be "cross-enclave data structures".
 * The request id will be an integer variable and will be unique for each call.
 */

/**
 *The life cycle of a cross-enclave data structure is as follows. First, the
 * non-enclave code allocates and initializes an object of the cross-enclave
 * data structure and then passes the pointer of the object to the enclave
 * code. Then, the enclave code creates an trusted object out of the given,
 * untrusted object; this is called "clone". This clone operation will do all
 * proper security checks. Finally, the enclave code can access and manipuate
 * its cloned object securely. 
 *
 */

struct fread_arg
{
    void *buf;
    ssize_t size;
    size_t nmemb;
    SGX_FILE stream;
    unsigned int request_id;
    ssize_t ret;
};

struct fwrite_arg
{
    void *buf;
    ssize_t size;
    size_t nmemb;
    SGX_FILE stream;
    unsigned int request_id;
    ssize_t ret;
};

struct read_arg
{
    int fd;
    void *buf;
    size_t count;
    unsigned int request_id;
    ssize_t ret;
};

struct write_arg
{
    int fd;
    const void *buf;
    size_t count;
    unsigned int request_id;
    ssize_t ret;
};

//Type definitions
typedef struct fread_arg fread_arg_zc;
typedef struct fwrite_arg fwrite_arg_zc;
typedef struct read_arg read_arg_zc;
typedef struct write_arg write_arg_zc;

//Request and response structs
struct zc_request
{
    void *args;
    unsigned int req_id;
};

struct zc_response
{
    void *args;
    unsigned int req_id;
};

typedef struct zc_request zc_req;
typedef struct zc_response zc_resp;

struct zc_req_node
{
    zc_req *req;
    struct zc_req_node *next;
};

struct zc_resp_node
{
    zc_req *req;
    struct zc_resp_node *next;
};

typedef struct zc_resp_node zc_resp_node;
typedef struct zc_req_node zc_req_node;

/**
 * request and response queues
 */
struct zc_response_queue
{
    unsigned int resp_count = 0; /* number of responses in queue */
    zc_resp_node *front;
    zc_resp_node *rear;
};

struct zc_request_queue
{
    unsigned int req_count = 0; /* number of responses in queue */
    zc_req_node *front;
    zc_req_node *rear;
};

typedef zc_response_queue zc_resp_q;
typedef zc_request_queue zc_req_q;

#endif /* ZC_ARGS_H */
