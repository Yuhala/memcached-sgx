
/*
 * Created on Tue Jul 21 2020
 *
 * Copyright (c) 2020 Peterson Yuhala, IIUN
 */

/** 
 * Quick note on TODOs: most of the routines should be simple to reimplement with ocalls. 
 * A few may require special attention. For example routines with struct or other complex 
 * types as return or param types.
*/
#include <stdio.h>
#include <unistd.h>

#include "graal_sgx_shim_switchless.h"
#include "graal_sgx_shim_switchless_generics.h"

#include "checks.h"  //for pointer checks
#include "Enclave.h" //for printf

#include "limits.h" // for SIZE_MAX

#include "switchless_buffer_t.h" // for resize_buffer_*



extern __thread struct buffer* switchless_buffer;
extern void** shim_switchless_functions;
extern void** shim_functions;


void empty_switchless(int repeats)
{
    GRAAL_SGX_INFO();

    *((int*) switchless_buffer->args) = repeats;
    switchless_buffer->ocall_handler_switchless = shim_switchless_functions[FN_TOKEN_EMPTY];
    switchless_buffer->ocall_handler = shim_functions[FN_TOKEN_EMPTY];
    ocall_switchless(switchless_buffer);
    switchless_buffer->status = BUFFER_UNUSED;
}

int fsync_switchless(int fd)
{
    int ret;
    ret = ret_int_args_int_switchless(shim_functions[FN_TOKEN_FSYNC], fd);
    switchless_buffer->status = BUFFER_UNUSED;
    return ret;
}

int dup2_switchless(int oldfd, int newfd)
{
    int ret;
    ret = ret_int_args_int_int_switchless(shim_functions[FN_TOKEN_DUP2], oldfd, newfd);
    switchless_buffer->status = BUFFER_UNUSED;
    return ret;
}

/*int open_switchless(const char *path, int oflag, ...); */

int close_switchless(int fd)
{
    int ret;
    ret = ret_int_args_int_switchless(shim_functions[FN_TOKEN_CLOSE], fd);
    switchless_buffer->status = BUFFER_UNUSED;
    return ret;
}

size_t fwrite_switchless(const void *ptr, size_t size, size_t nmemb, SGX_FILE stream)
{
    ssize_t ret;
    
    GRAAL_SGX_INFO();
    
    resize_buffer_args(switchless_buffer, size * nmemb + 2 * sizeof(size_t) + size * nmemb);
    resize_buffer_ret(switchless_buffer, sizeof(size_t));
    
    ((size_t*) switchless_buffer->args)[0] = size;
    ((size_t*) switchless_buffer->args)[1] = nmemb;
    ((SGX_FILE*) (switchless_buffer->args + 2 * sizeof(size_t)))[0] = stream;
    memcpy(switchless_buffer->args + 2 * sizeof(size_t) + sizeof(SGX_FILE), ptr, size * nmemb);
    switchless_buffer->ocall_handler_switchless = shim_switchless_functions[FN_TOKEN_FWRITE];
    switchless_buffer->ocall_handler = shim_functions[FN_TOKEN_FWRITE];
    ocall_switchless(switchless_buffer);
    ret = *((size_t*) switchless_buffer->ret);
    switchless_buffer->status = BUFFER_UNUSED;

    return ret;
}

int puts_switchless(const char* pathname)
{
    int ret;
    ret = ret_int_args_const_string_switchless(shim_functions[FN_TOKEN_PUTS], pathname, SIZE_MAX);
    switchless_buffer->status = BUFFER_UNUSED;
    return ret;
}

int unlink_switchless(const char* pathname)
{
    int ret;
    ret = ret_int_args_const_string_switchless(shim_functions[FN_TOKEN_UNLINK], pathname, PATH_MAX);
    switchless_buffer->status = BUFFER_UNUSED;
    return ret;
}

int rmdir_switchless(const char* pathname)
{
    int ret;
    ret = ret_int_args_const_string_switchless(shim_functions[FN_TOKEN_RMDIR], pathname, PATH_MAX);
    switchless_buffer->status = BUFFER_UNUSED;
    return ret;
}

int remove_switchless(const char* pathname)
{
    int ret;
    ret = ret_int_args_const_string_switchless(shim_functions[FN_TOKEN_REMOVE], pathname, PATH_MAX);
    switchless_buffer->status = BUFFER_UNUSED;
    return ret;
}


ssize_t read_switchless(int fd, void *buf, size_t count)
{
    ssize_t ret;
    
    GRAAL_SGX_INFO();
    
    resize_buffer_args(switchless_buffer, sizeof(int) + sizeof(size_t));
    resize_buffer_ret(switchless_buffer, sizeof(ssize_t) + count);
    
    ((int*) switchless_buffer->args)[0] = fd;
    ((size_t*) (switchless_buffer->args + sizeof(int)))[0] = count;
    switchless_buffer->ocall_handler_switchless = shim_switchless_functions[FN_TOKEN_READ];
    switchless_buffer->ocall_handler = shim_functions[FN_TOKEN_READ];
    ocall_switchless(switchless_buffer);
    memcpy(buf, switchless_buffer->ret + sizeof(size_t), count);
    ret = *((size_t*) switchless_buffer->ret);
    switchless_buffer->status = BUFFER_UNUSED;
    
    return ret;
}


ssize_t write_switchless(int fd, const void *buf, size_t count)
{
    ssize_t ret;
    
    GRAAL_SGX_INFO();
    
    resize_buffer_args(switchless_buffer, sizeof(int) + sizeof(size_t) + count);
    resize_buffer_ret(switchless_buffer, sizeof(ssize_t));
    
    ((int*) (switchless_buffer->args + count + sizeof(size_t)))[0] = fd;
    ((size_t*) switchless_buffer->args)[0] = count;
    memcpy(switchless_buffer->args + sizeof(size_t), buf, count);
    switchless_buffer->ocall_handler_switchless = shim_switchless_functions[FN_TOKEN_WRITE];
    switchless_buffer->ocall_handler = shim_functions[FN_TOKEN_WRITE];
    ocall_switchless(switchless_buffer);
    ret = *((size_t*) switchless_buffer->ret);
    switchless_buffer->status = BUFFER_UNUSED;

    return ret;
}

off64_t lseek64_switchless(int fd, off64_t offset, int whence)
{
    off64_t ret;

    GRAAL_SGX_INFO();

    resize_buffer_args(switchless_buffer, 2*sizeof(int) + sizeof(off64_t));
    resize_buffer_ret(switchless_buffer, sizeof(off64_t));

    ((int*) switchless_buffer->args)[0] = fd;
    ((off64_t*) (switchless_buffer->args + sizeof(int)))[0] = offset;
    ((int*) (switchless_buffer->args + sizeof(int) + sizeof(off64_t)))[0] = whence;
    switchless_buffer->ocall_handler_switchless = shim_switchless_functions[FN_TOKEN_LSEEK64];
    switchless_buffer->ocall_handler = shim_functions[FN_TOKEN_LSEEK64];
    ocall_switchless(switchless_buffer);
    ret = *((off64_t*) switchless_buffer->ret);
    switchless_buffer->status = BUFFER_UNUSED;

    return ret;
}

ssize_t sendmsg_switchless(int sockfd, const struct msghdr *msg, int flags)
{
    off64_t ret;

    GRAAL_SGX_INFO();

    resize_buffer_args(switchless_buffer, 2*sizeof(int) + sizeof(const struct msghdr*));
    resize_buffer_ret(switchless_buffer, sizeof(ssize_t));

    ((int*) switchless_buffer->args)[0] = sockfd;
    ((const struct msghdr**) (switchless_buffer->args + sizeof(int)))[0] = msg;
    ((int*) (switchless_buffer->args + sizeof(int) + sizeof(const struct msghdr*)))[0] = flags;
    switchless_buffer->ocall_handler_switchless = shim_switchless_functions[FN_TOKEN_SENDMSG];
    switchless_buffer->ocall_handler = shim_functions[FN_TOKEN_SENDMSG];
    ocall_switchless(switchless_buffer);
    ret = *((ssize_t*) switchless_buffer->ret);
    switchless_buffer->status = BUFFER_UNUSED;

    return ret;
}
