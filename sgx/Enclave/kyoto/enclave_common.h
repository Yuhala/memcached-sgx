/*
 * Created on Fri Nov 19 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * Common libs for in-enclave kyoto db
 */

#ifndef ENCLAVE_COMMON_H
#define ENCLAVE_COMMON_H

#define USE_SGX

#ifdef USE_SGX
#include "Enclave.h"
#include <sgx_thread.h>
#include <sgx/mman.h>
#else
#include <pthread.h>
#include <sys/mman.h>
#endif

#include "kyoto_logger_in.h"


//Type replacements for SGX runtime or not
#ifdef USE_SGX
#define MUTEX_TYPE sgx_thread_mutex_t
#else
#define MUTEX_TYPE pthread_mutex_t
#endif

#endif /* ENCLAVE_COMMON_H */
