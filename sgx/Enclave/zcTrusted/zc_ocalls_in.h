
/*
 * Created on Fri Oct 01 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * 
 * Small subset of shim lib functions implemented as zc switchless for our POC
 */

#ifndef ZC_OCALLS_IN_H
#define ZC_OCALLS_IN_H

#include <stdlib.h>
#include <sgx/sys/socket.h>
#include "struct/sgx_stdio_struct.h"

// io
ssize_t zc_read(int fd, void *buf, size_t count, int pool_index);
ssize_t zc_write(int fd, const void *buf, size_t count, int pool_index);
size_t zc_fwrite(const void *ptr, size_t size, size_t nmemb, SGX_FILE stream, int pool_index);
size_t zc_fread(void *ptr, size_t size, size_t nmemb, SGX_FILE stream, int pool_index);
int zc_fseeko(SGX_FILE stream, off_t offset, int whence, int pool_index);

// for kyoto cabinet
int zc_fsync(int fd, int pool_index);
void zc_sync(int pool_index);
int zc_ftruncate64(int fd, off_t length, int pool_index);

// net
ssize_t zc_sendmsg(int sockfd, const struct msghdr *msg, int flags, int pool_index);
void *zc_transmit_prepare(int pool_index);

//test
int zc_test(int a, int b, int pool_index);

//for benchmarking purposes
void zc_micro_f(int pool_index);
void zc_micro_g(int pool_index);

#endif /* ZC_OCALLS_H */
