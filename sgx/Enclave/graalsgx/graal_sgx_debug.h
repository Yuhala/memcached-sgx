
/*
 * Created on Thu Nov 25 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#ifndef GRAAL_SGX_DEBUG_H
#define GRAAL_SGX_DEBUG_H

//forward declarations
//int printf(const char *fmt, ...);

#define sgx_debug(A) printf("SGX error code: %x - in line %d of file %s (function %s)\n", \
                            A, __LINE__, __FILE__, __func__)

#define CHECK_STATUS(status)       \
    do                             \
    {                              \
        if (status != SGX_SUCCESS) \
        {                          \
            sgx_debug(status);     \
            abort();               \
        }                          \
    } while (0)

#endif /* GRAAL_SGX_DEBUG_H */
