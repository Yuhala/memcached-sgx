
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


unsigned int sleep_switchless(unsigned int secs)
{
    unsigned int ret;
    ret = ret_int_args_int_switchless(shim_functions[FN_TOKEN_SLEEP], secs);
    switchless_buffer->status = BUFFER_UNUSED;
    return ret;
}
