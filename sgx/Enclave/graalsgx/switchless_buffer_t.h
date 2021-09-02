#ifndef _SWITCHLESS_BUFFER_T_H
#define _SWITCHLESS_BUFFER_T_H

#define DEFAULT_BUFFER_ARG_SIZE 16
#define DEFAULT_BUFFER_RET_SIZE 16

#include <unistd.h>
#include "Enclave_t.h"


#if defined(__cplusplus)
extern "C"
{
#endif

    int resize_buffer_args(struct buffer* switchless_buffer, size_t new_size);
    int resize_buffer_ret(struct buffer* switchless_buffer, size_t new_size);    

#if defined(__cplusplus)
}
#endif


#endif /* ! _SWITCHLESS_BUFFER_T_H */
