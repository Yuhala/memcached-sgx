/*
 * Created on Fri Nov 19 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#ifndef ENCLAVE_COMMON_H
#define ENCLAVE_COMMON_H

#define USE_SGX

#ifdef USE_SGX

#include "Enclave.h"
#include <sgx_thread.h>
#include <sgx/mman.h>

#endif

#include "kyoto_logger_in.h"

#endif /* ENCLAVE_COMMON_H */
