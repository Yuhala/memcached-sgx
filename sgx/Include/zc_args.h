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

#include "memcached/mpool.h"

#define ZC_BUFFER_SZ 1024 * 1024 /* 1mb default buffer size should be enough for static buffers */

#define ZC_QUEUE_CAPACITY 1024 /* capacity of request and response queues */
#define ZC_FREE_ID -1          /* free arg slots will have this request id */

#define POOL_SIZE 32 * 1024 * 1024 /* surely 32 mb should be enough for realistic tests/benchmarks */
#define NUM_POOLS 10               /* the number of memory pools to create; == number max threads in enclave */

#define ZC_REQUEST_DONE 1

/**
 * structure containing pointers to argument buffers. 
 * Some of these structures will be "cross-enclave data structures".
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

//---------------------- zc args  -----------------------
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
    void *buf;
    size_t count;
    unsigned int request_id;
    ssize_t ret;
};

//Type definitions
typedef struct fread_arg fread_arg_zc;
typedef struct fwrite_arg fwrite_arg_zc;
typedef struct read_arg read_arg_zc;
typedef struct write_arg write_arg_zc;

//Special types for each zc switchless routine
enum zc_routine
{
    ZC_FREAD,
    ZC_FWRITE,
    ZC_READ,
    ZC_WRITE,
    ZC_SENDMSG
};
typedef enum zc_routine zc_routine;

//---------------------- zc req/resp queues -----------------------
//Request and response structs
struct zc_request
{
    void *args;
    zc_routine func_name;
    unsigned int req_id;
    volatile int is_done; /* do not cache this int */
};

struct zc_response
{
    void *args;
    zc_routine func_name;
    unsigned int req_id;
};

typedef struct zc_request zc_req;
typedef struct zc_response zc_resp;

struct zc_req_node
{
    zc_req *req;
    struct zc_req_node *next; /* resp node behind this node */
};

struct zc_resp_node
{
    zc_resp *resp;
    struct zc_resp_node *next; /* req node behind this node */
};

typedef struct zc_resp_node zc_resp_node;
typedef struct zc_req_node zc_req_node;

/**
 * request and response queues
 */
struct zc_response_queue
{
    unsigned int resp_count = 0; /* number of completed requests in queue */
    zc_req_node *front;
    zc_req_node *rear;
};

struct zc_request_queue
{
    unsigned int req_count = 0; /* number of requests in queue */
    zc_req_node *front;
    zc_req_node *rear;
};

/**
 *  generic queue for requests; we may not need a special response queue
 */
struct zc_queue
{
    unsigned int count = 0; /* number of requests/items in queue */
    zc_req_node *front;
    zc_req_node *rear;
};

typedef zc_response_queue zc_resp_q;
typedef zc_request_queue zc_req_q;

enum zc_queue_type
{
    ZC_REQ_Q = 0,
    ZC_RESP_Q

};
typedef enum zc_queue_type zc_q_type;

//---------------------- zc arg list -----------------------

/**
 * Argument list/slots for different libc routines/ocalls. This list/struct will have an entry for 
 * each switchless ocall routine. 
 * The size of each argument array will depend on the number of the size of the request queue.
 */

struct zc_arg_list
{
    fread_arg_zc *fread_arg_array;
    fwrite_arg_zc *fwrite_arg_array;
    read_arg_zc *read_arg_array;
    write_arg_zc *write_arg_array;
};

typedef zc_arg_list zc_arg_list;

/**
 * Structures to manage argument slots
 */

struct zc_arg_slot
{
    int data; /* index of a free slot in an arg buffer array */
    struct zc_arg_slot *next;
};

typedef struct zc_arg_slot zc_arg_slot;

//---------------------- zc memory pool -----------------------
struct zc_mpool
{
    mpool_t *memory_pools[NUM_POOLS];
};
typedef struct zc_mpool zc_mpool;

#define ZC_ASSERT(EXPR)                                \
    do                                                 \
    {                                                  \
        if (!(EXPR))                                   \
        {                                              \
            printf(                                    \
                "ASSERTION FAILED: %s (%s: %d: %s)\n", \
                #EXPR,                                 \
                __FILE__,                              \
                __LINE__,                              \
                __FUNCTION__);                         \
            abort();                                   \
        }                                              \
    } while (0)

#endif /* ZC_ARGS_H */
