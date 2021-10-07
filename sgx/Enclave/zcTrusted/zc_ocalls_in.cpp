/*
 * Created on Fri Oct 01 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * Small subset of shim lib functions implemented as zc switchless for our POC
 * It is important to understand the semantics of each function to implement them correctly.
 */

#include "Enclave.h"
#include "zc_in.h"
#include "zc_ocalls_in.h"
#include "zc_queues_in.h" /* for zc_malloc */

ssize_t zc_read(int fd, void *buf, size_t count, int pool_index)
{
    //log_zc_routine(__func__);
    // allocate memory for args
    read_arg_zc *arg = (read_arg_zc *)zc_malloc(pool_index, sizeof(read_arg_zc));
    // copy args from enclave to untrusted memory
    arg->fd = fd;
    arg->count = count;
    arg->buf = zc_malloc(pool_index, count);

    // do request
    zc_req *request = (zc_req *)zc_malloc(pool_index, sizeof(zc_req));
    request->args = (void *)arg;
    request->func_name = ZC_READ;
    request->is_done = 1;
    do_zc_switchless_request(request, pool_index);

    ssize_t ret = ((read_arg_zc *)request->args)->ret;

    // copy response to enclave if needed
    mempcpy(buf, arg->buf, ret);

    // release worker/memory pool
    release_worker(pool_index);

    // return
    return ret;
}

ssize_t zc_write(int fd, const void *buf, size_t count, int pool_index)
{
    //log_zc_routine(__func__);
    // allocate memory for args
    write_arg_zc *arg = (write_arg_zc *)zc_malloc(pool_index, sizeof(write_arg_zc));
    // copy args from enclave to untrusted memory
    arg->fd = fd;
    arg->count = count;
    arg->buf = zc_malloc(pool_index, count);
    //TODO:pointer checks
    memcpy(arg->buf, buf, count);

    // do request
    zc_req *request = (zc_req *)zc_malloc(pool_index, sizeof(zc_req));
    request->args = (void *)arg;
    request->func_name = ZC_WRITE;
    request->is_done = 1;
    do_zc_switchless_request(request, pool_index);

    // copy response to enclave if needed

    // release worker/memory pool
    release_worker(pool_index);

    // return
    return ((write_arg_zc *)request->args)->ret;
}

ssize_t zc_sendmsg(int sockfd, const struct msghdr *msg, int flags, int pool_index)
{
    //log_zc_routine(__func__);
    // allocate memory for args
    //_arg_zc *arg = (_arg_zc *)zc_malloc(sizeof(_arg_zc));
    // copy args from enclave to untrusted memory

    // do request
    zc_req *request = (zc_req *)zc_malloc(pool_index, sizeof(zc_req));
    //request->args = (void*)arg;
    request->func_name = ZC_SENDMSG;
    request->is_done = 1;
    //TODO: not complete
    do_zc_switchless_request(request, pool_index);

    // copy response to enclave if needed

    // release worker/memory pool
    release_worker(pool_index);

    // return
    return 0;
}

size_t zc_fwrite(const void *ptr, size_t size, size_t nmemb, SGX_FILE stream, int pool_index)
{
    //log_zc_routine(__func__);
    // allocate memory for args
    fwrite_arg_zc *arg = (fwrite_arg_zc *)zc_malloc(pool_index, sizeof(fwrite_arg_zc));
    // copy args from enclave to untrusted memory
    arg->size = size;
    arg->nmemb = nmemb;
    arg->stream = stream;
    size_t total_bytes = size * nmemb;
    arg->buf = zc_malloc(pool_index, total_bytes);
    //TODO: do we do pointer checks ?
    memcpy(arg->buf, ptr, total_bytes);

    // do request
    zc_req *request = (zc_req *)zc_malloc(pool_index, sizeof(zc_req));
    request->args = (void *)arg;
    request->func_name = ZC_FWRITE;
    request->is_done = 1;
    do_zc_switchless_request(request, pool_index);

    // copy response to enclave if needed

    // release worker/memory pool
    /**
     * pyuhala: can use pool_index variable but it seems 
     * caller is not changing the pool status
     */
    release_worker(pool_index);

    // return
    ssize_t ret = ((fwrite_arg_zc *)request->args)->ret;
    //printf("---------------zc fwrite ret: %d ---------------------\n", ret);
    return ret;
}

size_t zc_fread(void *ptr, size_t size, size_t nmemb, SGX_FILE stream, int pool_index)
{
    //log_zc_routine(__func__);
    // allocate memory for args
    fread_arg_zc *arg = (fread_arg_zc *)zc_malloc(pool_index, sizeof(fread_arg_zc));
    // copy args from enclave to untrusted memory
    arg->size = size;
    arg->nmemb = nmemb;
    arg->stream = stream;
    size_t total_bytes = size * nmemb;
    arg->buf = zc_malloc(pool_index, total_bytes);

    // do request
    zc_req *request = (zc_req *)zc_malloc(pool_index, sizeof(zc_req));
    request->args = (void *)arg;
    request->func_name = ZC_FREAD;
    request->is_done = 1;

    do_zc_switchless_request(request, pool_index);

    ssize_t ret = ((fread_arg_zc *)request->args)->ret;

    // copy response to enclave if needed
    mempcpy(ptr, arg->buf, ret);

    // release worker/memory pool
    release_worker(pool_index);

    // return
    //printf("--------------- zc fread expected: %d actually read: %d ---------------------\n", total_bytes, ret);
    return ret;
}

int zc_fseeko(SGX_FILE stream, off_t offset, int whence, int pool_index)
{
    //log_zc_routine(__func__);
    // allocate memory for args
    fseeko_arg_zc *arg = (fseeko_arg_zc *)zc_malloc(pool_index, sizeof(fseeko_arg_zc));
    // copy args from enclave to untrusted memory
    arg->stream = stream;
    arg->offset = offset;
    arg->whence = whence;

    // do request
    zc_req *request = (zc_req *)zc_malloc(pool_index, sizeof(zc_req));
    request->args = (void *)arg;
    request->func_name = ZC_FSEEKO;
    request->is_done = 1;

    do_zc_switchless_request(request, pool_index);

    // copy response to enclave if needed

    // release worker/memory pool
    release_worker(pool_index);

    // return
    int ret = ((fseeko_arg_zc *)request->args)->ret;
    //printf("---------------zc fread ret: %d ---------------------\n", ret);
    return ret;
}

int zc_test(int a, int b, int pool_index){
    //log_zc_routine(__func__);
    // allocate memory for args
    test_arg_zc *arg = (test_arg_zc *)zc_malloc(pool_index, sizeof(test_arg_zc));
    // copy args from enclave to untrusted memory
    arg->a = a;
    arg->b = b;
    

    // do request
    zc_req *request = (zc_req *)zc_malloc(pool_index, sizeof(zc_req));
    request->args = (void *)arg;
    request->func_name = ZC_TEST;
    request->is_done = 1;

    do_zc_switchless_request(request, pool_index);

    // copy response to enclave if needed

    // release worker/memory pool
    release_worker(pool_index);

    // return
    int ret = ((test_arg_zc *)request->args)->ret;
    //printf("---------------zc fread ret: %d ---------------------\n", ret);
    return ret;
}