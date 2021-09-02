/*
 * Created on Tue Jul 21 2020
 *
 * Copyright (c) 2020 Peterson Yuhala, IIUN
 * Some ideas were taken from Panoply code
 */
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/times.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include "struct/sgx_stdio_struct.h"
#include "Enclave_u.h"
#include <errno.h>

#include "graal_sgx_shim_switchless_u.h"

#include "io.h"

/* void empty(int repeats) */
void ocall_empty_switchless(struct buffer* switchless_buffer)
{
    int repeats;
    int i;

    repeats = *((int*) switchless_buffer->args);
    for (i=0; i<repeats; i++)
	asm volatile("pause");
}

/* size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE* stream) */
void ocall_fwrite_switchless(struct buffer* switchless_buffer)
{
    size_t ret;
    size_t size;
    size_t nmemb;
    SGX_FILE stream_sgx;
    FILE* stream;
    const void* ptr;

    size = ((size_t*) switchless_buffer->args)[0];
    nmemb = ((size_t*) switchless_buffer->args)[1];
    stream_sgx = *((SGX_FILE*) (switchless_buffer->args + 2 * sizeof(size_t)));
    stream = getFile(stream_sgx);
    ptr = switchless_buffer->args + 2 * sizeof(size_t) + sizeof(SGX_FILE);
    ret = ((ssize_t (*) (const void*, size_t, size_t, FILE*)) switchless_buffer->ocall_handler)(ptr, size, nmemb, stream);
    *((size_t*) switchless_buffer->ret) = ret;
}

/* ssize_t read(int fd, void *buf, size_t count) */
void ocall_read_switchless(struct buffer* switchless_buffer)
{
    ssize_t ret;
    int fd;
    size_t count;
    void* buf;

    fd = *((int*) switchless_buffer->args);
    count = *((size_t*) (switchless_buffer->args + sizeof(int)));
    buf = switchless_buffer->ret + sizeof(size_t);
    ret = ((ssize_t (*) (int, void*, size_t)) switchless_buffer->ocall_handler)(fd, buf, count);
    *((ssize_t*) switchless_buffer->ret) = ret;
}

/* ssize_t write(int fd, const void *buf, size_t count) */
void ocall_write_switchless(struct buffer* switchless_buffer)
{
    ssize_t ret;
    int fd;
    size_t count;
    const void* buf;

    count = *((size_t*) switchless_buffer->args);
    fd = *((int*) (switchless_buffer->args + count + sizeof(size_t)));
    buf = switchless_buffer->args + sizeof(size_t);
    ret = ((ssize_t (*) (int, const void*, size_t)) switchless_buffer->ocall_handler)(fd, buf, count);
    *((ssize_t*) switchless_buffer->ret) = ret;
}

void ocall_lseek64_switchless(struct buffer* switchless_buffer)
{
    off64_t ret;
    int fd, whence;
    off64_t offset;

    fd = ((int*) switchless_buffer->args)[0];
    offset = ((off64_t*) (switchless_buffer->args + sizeof(int)))[0];
    whence = ((int*) (switchless_buffer->args + sizeof(int) + sizeof(off64_t)))[0];
    ret = ((off64_t (*) (int,off64_t,int)) switchless_buffer->ocall_handler)(fd, offset, whence);
    *((off64_t*) switchless_buffer->ret) = ret;
}
