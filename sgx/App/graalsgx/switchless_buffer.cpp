#include "switchless_buffer.h"
#include <stdlib.h>
#include "Enclave_u.h"


int init_switchless_buffer(struct buffer* switchless_buffer)
{
    int rv = 0;

    switchless_buffer->ocall_handler = NULL;
    switchless_buffer->ocall_handler_switchless = NULL;
    if ((switchless_buffer->args = malloc(DEFAULT_BUFFER_ARG_SIZE)) == NULL)
        rv = 1;
    else if ((switchless_buffer->ret = malloc(DEFAULT_BUFFER_RET_SIZE)) == NULL)
        rv = 1;
    switchless_buffer->spinlock = 0;
    switchless_buffer->status = BUFFER_UNUSED;
    switchless_buffer->args_size = DEFAULT_BUFFER_ARG_SIZE;
    switchless_buffer->ret_size = DEFAULT_BUFFER_RET_SIZE;

    return rv;
}
