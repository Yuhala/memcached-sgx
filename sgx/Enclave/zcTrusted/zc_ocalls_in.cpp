/*
 * Created on Fri Oct 01 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * Small subset of shim lib functions implemented as zc switchless for our POC
 * It is important to understand the semantics of each function to implement them correctly.
 */

#include "zc_in.h"
#include "zc_ocalls_in.h"
#include "zc_queues_in.h" /* for zc_malloc */

ssize_t zc_read(int fd, void *buf, size_t count)
{
    // allocate memory for args
    read_arg_zc *arg = (read_arg_zc *)zc_malloc(sizeof(read_arg_zc));
    // copy args from enclave to untrusted memory
    arg->fd = fd;
    arg->count = count;
    arg->buf = zc_malloc(count);

    // do request
    zc_req *request = (zc_req *)zc_malloc(sizeof(zc_req));
    request->args = (void *)arg;
    request->func_name = ZC_READ;
    request->is_done = 0;
    do_zc_switchless_request(request);

    // wait for response
    ZC_REQUEST_WAIT(&request->is_done);

    // copy response to enclave if needed
    mempcpy(buf, arg->buf, count);

    // return
    return ((read_arg_zc *)request->args)->ret;
}

ssize_t zc_write(int fd, const void *buf, size_t count)
{
    // allocate memory for args
    write_arg_zc *arg = (write_arg_zc *)zc_malloc(sizeof(write_arg_zc));
    // copy args from enclave to untrusted memory
    arg->fd = fd;
    arg->count = count;
    arg->buf = zc_malloc(count);
    //TODO:pointer checks
    memcpy(arg->buf, buf, count);

    // do request
    zc_req *request = (zc_req *)zc_malloc(sizeof(zc_req));
    request->args = (void *)arg;
    request->func_name = ZC_WRITE;
    request->is_done = 0;
    do_zc_switchless_request(request);

    // wait for response
    ZC_REQUEST_WAIT(&request->is_done);

    // copy response to enclave if needed

    // return
    return ((write_arg_zc *)request->args)->ret;
}

ssize_t zc_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    // allocate memory for args
    //_arg_zc *arg = (_arg_zc *)zc_malloc(sizeof(_arg_zc));
    // copy args from enclave to untrusted memory

    // do request
    zc_req *request = (zc_req *)zc_malloc(sizeof(zc_req));
    //request->args = (void*)arg;
    request->func_name = ZC_SENDMSG;
    request->is_done = 0;

    do_zc_switchless_request(request);

    // wait for response
    ZC_REQUEST_WAIT(&request->is_done);

    // copy response to enclave if needed

    // return
    return 0;
}

size_t zc_fwrite(const void *ptr, size_t size, size_t nmemb, SGX_FILE stream)
{
    // allocate memory for args
    fwrite_arg_zc *arg = (fwrite_arg_zc *)zc_malloc(sizeof(fwrite_arg_zc));
    // copy args from enclave to untrusted memory
    arg->size = size;
    arg->nmemb = nmemb;
    arg->stream = stream;
    size_t total_bytes = size * nmemb;
    arg->buf = zc_malloc(total_bytes);
    //TODO:pointer checks
    memcpy(arg->buf, ptr, total_bytes);

    // do request
    zc_req *request = (zc_req *)zc_malloc(sizeof(zc_req));
    request->args = (void *)arg;
    request->func_name = ZC_FWRITE;
    request->is_done = 0;
    do_zc_switchless_request(request);

    // wait for response
    ZC_REQUEST_WAIT(&request->is_done);

    // copy response to enclave if needed

    // return
    return ((fwrite_arg_zc *)request->args)->ret;
}

size_t zc_fread(void *ptr, size_t size, size_t nmemb, SGX_FILE stream)
{
    // allocate memory for args
    fread_arg_zc *arg = (fread_arg_zc *)zc_malloc(sizeof(fread_arg_zc));
    // copy args from enclave to untrusted memory
    arg->size = size;
    arg->nmemb = nmemb;
    arg->stream = stream;
    size_t total_bytes = size * nmemb;
    arg->buf = zc_malloc(total_bytes);

    // do request
    zc_req *request = (zc_req *)zc_malloc(sizeof(zc_req));
    request->args = (void *)arg;
    request->func_name = ZC_FREAD;
    request->is_done = 0;
    do_zc_switchless_request(request);

    // wait for response
    ZC_REQUEST_WAIT(&request->is_done);

    // copy response to enclave if needed
    mempcpy(ptr, arg->buf, total_bytes);

    // return
    return ((fread_arg_zc *)request->args)->ret;
}
