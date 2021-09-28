/*
 * Created on Wed Jul 15 2020
 *
 * Copyright (c) 2020 Peterson Yuhala, IIUN
 */

#ifndef GRAAL_SGX_SHIM_SWITCHLESS_H
#define GRAAL_SGX_SHIM_SWITCHLESS_H

//#define __USE_LARGEFILE64 //for stat64

//used by some reimplementations. For testing purposes --PYuhala
#define GRAAL_SGX_STACK_SIZE 0x200000
#define GRAAL_SGX_PAGESIZE 4096
#define GRAAL_SGX_GUARDSIZE GRAAL_SGX_PAGESIZE
#define GRAAL_SCHED_POLICY 0
#define COND_NWAITERS_SHIFT 1
#define CLOCK_MONOTONIC 0
#define CLOCK_REALTIME 1
#define NUM_MAPS 100000
#define Pause() __asm__ __volatile__("pause" \
                                     :       \
                                     :       \
                                     : "memory")

#define __USE_LARGEFILE64
//sys
#include <sgx/sys/types.h>
#include <sgx/sys/stat.h>
#include <sgx/pwd.h>
#include <sgx/sys/utsname.h>
#include <sgx/sys/resource.h>
#include <sgx/linux/limits.h>
#include <stdlib.h>
#include <string.h>
#include <sgx/signal.h>
#include <unistd.h>
#include <sgx/netdb.h>
#include <struct/sgx_fcntl_struct.h>
#include <sgx/sys/wait.h>
//#include <sgx/sys/statvfs.h>

//io
#include <stdio.h>

#include <sgx/dirent.h>
//#include <struct/sgx_stdio_struct.h>
//#include <struct/sgx_sysstat_struct.h>

//net
#include <sgx/sys/socket.h>
#include <sgx/arpa/inet.h>
#include <sgx/sys/epoll.h>
#include <sgx/sys/uio.h>
#include <sgx/sys/poll.h>
#include <sgx/sys/epoll.h>

//threads
//#include <pthread.h>
#include <struct/sgx_pthread_struct.h>
#include <struct/sgx_stdio_struct.h>
#include <sgx_thread.h>
//#include <sgx_pthread.h>

//TODO
typedef unsigned char Byte;
typedef unsigned char Bytef;
typedef long off64_t;
typedef size_t z_size_t;
typedef void DIR;
//typedef int z_streamp;

//extern char **environ;
// This prevents "name mangling" by g++ ---> PYuhala
#if defined(__cplusplus)
extern "C"
{
#endif

    //clock
    unsigned int sleep_switchless(unsigned int secs);
    //io
    void empty_switchless(int repeats);
    int fsync_switchless(int fd);
    int dup2_switchless(int oldfd, int newfd);
    //int open(const char *path, int oflag, ...);
    int close_switchless(int fd);
    size_t fwrite_switchless(const void* ptr, size_t size, size_t nmemb, SGX_FILE stream);
    size_t fread_switchless(void* ptr, size_t size, size_t nmemb, SGX_FILE stream);
    int puts_switchless(const char* s);
    int unlink_switchless(const char* pathname);
    int rmdir_switchless(const char* pathname);
    int remove_switchless(const char* pathname);
    ssize_t read_switchless(int fd, void *buf, size_t count);
    ssize_t write_switchless(int fd, const void *buf, size_t count);
    off64_t lseek64_switchless(int fd, off64_t offset, int whence);
    ssize_t sendmsg_switchless(int sockfd, const struct msghdr *msg, int flags);
    void* transmit_prepare_switchless(void);


#if defined(__cplusplus)
}
#endif

#endif /* GRAAL_SGX_SHIM_SWITCHLESS_H */
