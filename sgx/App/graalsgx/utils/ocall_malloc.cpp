#include "ocall_malloc.h"
#include <stdlib.h>
#include "ocall_logger.h"
#include "Enclave_u.h"

/* Allocates untrusted memory */
void* ocall_malloc(size_t size)
{
    log_ocall(__func__);
    return malloc(size);
}

/* Reallocates untrusted memory */
void* ocall_realloc(void* ptr, size_t size)
{
    log_ocall(__func__);
    return realloc(ptr, size);
}
