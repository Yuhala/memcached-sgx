#ifndef _OCALL_MALLOC_H
#define _OCALL_MALLOC_H

#include <stdlib.h>

#if defined(__cplusplus)
extern "C"
{
#endif

    void* ocall_malloc(size_t size);
    void* ocall_realloc(void* ptr, size_t size);

#if defined(__cplusplus)
}
#endif

#endif /* _OCALL_MALLOC_H */
