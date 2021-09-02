
/*
 * Created on Tue Jul 21 2020
 *
 * Copyright (c) 2020 Peterson Yuhala, IIUN
 */

/** 
 * Quick note on TODOs: most of the routines should be simple to reimplement with ocalls. 
 * A few may require special attention. For example routines with struct or other complex 
 * types as return or param types.
*/
#include <stdio.h>
#include <unistd.h>

#include "graal_sgx_shim_switchless.h"
#include "graal_sgx_shim_switchless_generics.h"

#include "checks.h"  //for pointer checks
#include "Enclave.h" //for printf

#include "switchless_buffer_t.h" // for resize_buffer_*



extern __thread struct buffer* switchless_buffer;
extern void** shim_switchless_functions;
extern void** shim_functions;


int ret_int_args_int_switchless(void* ocall_handler, int arg1)
{
    int ret;
    
    GRAAL_SGX_INFO();
    
    resize_buffer_args(switchless_buffer, sizeof(int));
    resize_buffer_ret(switchless_buffer, sizeof(int));
    
    ((int*) switchless_buffer->args)[0] = arg1;
    switchless_buffer->ocall_handler_switchless = shim_switchless_functions[FN_TOKEN_CLOSE];
    switchless_buffer->ocall_handler = ocall_handler;
    ocall_switchless(switchless_buffer);
    ret = *((int*) switchless_buffer->ret);

    return ret;
}

int ret_int_args_int_int_switchless(void* ocall_handler, int arg1, int arg2)
{
    int ret;
    
    GRAAL_SGX_INFO();
    
    resize_buffer_args(switchless_buffer, 2*sizeof(int));
    resize_buffer_ret(switchless_buffer, sizeof(int));
    
    ((int*) switchless_buffer->args)[0] = arg1;
    ((int*) switchless_buffer->args)[1] = arg2;
    switchless_buffer->ocall_handler_switchless = shim_switchless_functions[FN_TOKEN_DUP2];
    switchless_buffer->ocall_handler = ocall_handler;
    ocall_switchless(switchless_buffer);
    ret = *((int*) switchless_buffer->ret);

    return ret;
}

size_t min(size_t a, size_t b)
{
    return a < b ? a : b;
}

int ret_int_args_const_string_switchless(void* ocall_handler, const char* s, size_t maxlen)
{
    int ret;
    size_t len;

    GRAAL_SGX_INFO();

    len = min(maxlen, strnlen(s, maxlen) + 1);

    resize_buffer_args(switchless_buffer, len);
    resize_buffer_ret(switchless_buffer, sizeof(int));

    memcpy(switchless_buffer->args, s, len);
    switchless_buffer->ocall_handler_switchless = shim_switchless_functions[FN_TOKEN_UNLINK];
    switchless_buffer->ocall_handler = ocall_handler;
    ocall_switchless(switchless_buffer);
    ret = *((int*) switchless_buffer->ret);

    return ret;
}
