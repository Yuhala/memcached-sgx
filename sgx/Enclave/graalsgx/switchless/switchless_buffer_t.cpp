#include "switchless_buffer_t.h"
#include <stdlib.h>
#include "Enclave_t.h"


int resize_buffer_args(struct buffer* switchless_buffer, size_t new_size)
{
    int ret;

    if (new_size <= switchless_buffer->args_size)
	ret = 0;
    else
    {
	if(ocall_realloc(&switchless_buffer->args, switchless_buffer->args, new_size) != SGX_SUCCESS)
	    ret = 1;
	else if (switchless_buffer->args == NULL)
	    ret = 1;
	else
	{
	    ret = 0;
	    switchless_buffer->args_size = new_size;
	}
    }

    return ret;
}

int resize_buffer_ret(struct buffer* switchless_buffer, size_t new_size)
{
    int ret;

    if (new_size <= switchless_buffer->ret_size)
	ret = 0;
    else
    {
	if(ocall_realloc(&switchless_buffer->ret, switchless_buffer->ret, new_size) != SGX_SUCCESS)
	    ret = 1;
	else if (switchless_buffer->ret == NULL)
	    ret = 1;
	else
	{
	    ret = 0;
	    switchless_buffer->ret_size = new_size;
	}
    }

    return ret;
}
