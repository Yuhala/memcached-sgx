/*
 * Created on Wed Jul 15 2020
 *
 * Copyright (c) 2020 Peterson Yuhala, IIUN
 */

#ifndef GRAAL_SGX_SHIM_SWITCHLESS_GENERICS_H
#define GRAAL_SGX_SHIM_SWITCHLESS_GENERICS_H

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

    int ret_int_args_int_switchless(void* ocall_handler, int arg1);
    int ret_int_args_int_int_switchless(void* ocall_handler, int arg1, int arg2);
    int ret_int_args_const_string_switchless(void* ocall_handler, const char* arg1, size_t maxlen);


#if defined(__cplusplus)
}
#endif

#endif /* GRAAL_SGX_SHIM_SWITCHLESS_GENERICS_H */
