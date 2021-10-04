
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

ssize_t zc_read(int fd, void *buf, size_t count, int pool_index);
ssize_t zc_write(int fd, const void *buf, size_t count, int pool_index);
ssize_t zc_sendmsg(int sockfd, const struct msghdr *msg, int flags, int pool_index);
size_t zc_fwrite(const void *ptr, size_t size, size_t nmemb, SGX_FILE stream, int pool_index);
size_t zc_fread(void *ptr, size_t size, size_t nmemb, SGX_FILE stream, int pool_index);

#endif /* ZC_OCALLS_H */
