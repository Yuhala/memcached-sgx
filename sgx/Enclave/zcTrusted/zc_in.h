
/*
 * Created on Tue Sep 28 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * 
 * See here for cost of cpu pause: https://community.intel.com/t5/Intel-ISA-Extensions/Pause-instruction-cost-and-proper-use-in-spin-loops/m-p/1137387
 */

#ifndef ZC_IN_H
#define ZC_IN_H

#include "zc_types.h"

void do_zc_switchless_request(zc_req *request, unsigned int pool_index);
int reserve_worker();
void release_worker(unsigned int pool_index);
void ZC_REQUEST_WAIT(volatile int *isDone);
int get_free_pool();


//__atomic_store_n(&, val, __ATOMIC_RELAXED);

//logging
void log_zc_routine(const char *func);



#if defined(__cplusplus)
extern "C"
{
#endif

#if defined(__cplusplus)
}
#endif
#endif /* ZC_IN_H */
