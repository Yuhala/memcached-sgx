/*
 * Created on Wed Sep 29 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * 
 * For the proof of concept I implement specific structures which will hold the 
 * arguments of each switchless function. Untrusted memory pools will be pre-allocated for each enclave thread 
 * on which switchless requests + arguments will be allocated.
 * ZC == zero config (as in zero config/dynamic switchless call system)
 */

#ifndef ZC_TYPES_H
#define ZC_TYPES_H

#include <sys/types.h>
#include "struct/sgx_stdio_struct.h"

#include "memcached/mpool.h"

#define ZC_BUFFER_SZ 1024 * 1024 /* 1mb default buffer size should be enough for static buffers */

#define ZC_QUEUE_CAPACITY 1024 /* capacity of request and response queues */
#define ZC_FREE_ID -1          /* free arg slots will have this request id */

#define ZC_NO_FREE_POOL -1 /* if there is not free pool in the pool array return -1 index */

#define POOL_SIZE 64 * 1024 * 1024 /* surely 64 mb should be enough for realistic tests/benchmarks */
#define NUM_POOLS 8                /* the number of memory pools to create; == number max threads in enclave */

#define ZC_REQUEST_DONE 1

#define ZC_SPINLOCK 0

#define STALE_REQUEST -1234 /* magic number to detect stale requests in pools */

#define SCHED_PAUSE 1

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

struct fseeko_arg
{
    SGX_FILE stream;
    off_t offset;
    int whence;
    int ret;
};

struct sendmsg_arg
{
    int sockfd;
    void *msg_header;
    int flags;
    ssize_t ret;
};

struct transmit_prepare_arg
{
    void *ret;
};

struct test_arg
{
    int a;
    int b;
    int ret;
};

struct fsync_arg
{
    int fd;
    int ret;
};

struct sync_arg
{
    int ret;
};

struct no_arg
{
    int ret;
};

struct ftruncate64_arg
{
    int fd;
    off_t length;
    int ret;
};

//Type definitions
typedef struct fread_arg fread_arg_zc;
typedef struct fwrite_arg fwrite_arg_zc;
typedef struct read_arg read_arg_zc;
typedef struct write_arg write_arg_zc;
typedef struct fseeko_arg fseeko_arg_zc;
typedef struct sendmsg_arg sendmsg_arg_zc;
typedef struct transmit_prepare_arg transmit_prepare_arg_zc;

typedef struct test_arg test_arg_zc;

typedef struct fsync_arg fsync_arg_zc;
typedef struct sync_arg sync_arg_zc;
typedef struct ftruncate64_arg ftruncate64_arg_zc;

typedef struct no_arg no_arg_zc;

//Special types for each zc switchless routine
enum zc_routine
{
    ZC_FREAD = 0,
    ZC_FWRITE,
    ZC_READ,
    ZC_WRITE,
    ZC_SENDMSG,
    ZC_TRANSMIT_PREPARE,
    ZC_FSEEKO,
    ZC_FSYNC,
    ZC_SYNC,
    ZC_FTRUNCATE64,
    ZC_TEST,
    ZC_F,
    ZC_G
};
typedef enum zc_routine zc_routine;

//---------------------- zc req/resp queues -----------------------
//Request and response structs
struct zc_request
{
    void *args;
    zc_routine func_name;
    int req_status;
    //volatile int is_done;        /* do not cache this int */
    volatile int is_done;        /* do not cache this int */
    unsigned int req_pool_index; /* pool index of worker thread */
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

typedef struct zc_response_queue zc_resp_q;
typedef struct zc_request_queue zc_req_q;

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

typedef struct zc_arg_list zc_arg_list;

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

/**
 * Memory pool status. Based on Michael Paper's worker status design
 */

typedef enum
{
    UNUSED = 0, /* buffer can be used by callers; only set by worker */
    RESERVED,
    PROCESSING,
    WAITING,
    PAUSED, /* pause worker */
    DONE,   /* state immediately after a caller completes its request */
    EXIT,
    INACTIVE /* pool status at start of program */

} zc_pool_status;

struct zc_mpool
{
    mpool_t *pool;
    unsigned int pool_id;
    volatile int curr_user_id; /* temp unique identifier added by caller/enclave thread using this pool atm */
    unsigned int active;       /* is this pool allocated to a worker (1) or not (0) */
    volatile int pool_status;
    volatile int pool_lock;       /* used by spin locks for a thread changing pool status */
    volatile int scheduler_pause; /* scheduler changes this value to 1 so thread pauses after treating request */

    zc_req *request; /* caller request */
};

typedef struct zc_mpool zc_mpool;

struct zc_mpool_array
{
    zc_mpool **memory_pools;
    int num_pools;
};

struct zc_worker_args
{
    int pool_index;
    zc_mpool *worker_pool;
    int worker_id;
};

struct zc_stats
{
    unsigned int num_zc_swtless_calls;
    unsigned int num_zc_fallback_calls;
    unsigned int max_workers;
};

typedef zc_stats zc_stats;

typedef struct zc_worker_args zc_worker_args;

typedef struct zc_mpool_array zc_mpool_array;

#define ZC_PAUSE() __asm__ __volatile__("pause" \
                                        :       \
                                        :       \
                                        : "memory")

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

#define ZC_DEBUG_ASSERT(EXPR) \
    do                        \
    {                         \
        if (!(EXPR))          \
        {                     \
                              \
            abort();          \
        }                     \
    } while (0)

#endif /* ZC_TYPES_H */
