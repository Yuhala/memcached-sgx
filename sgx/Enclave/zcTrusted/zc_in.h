
/*
 * Created on Tue Sep 28 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * 
 * See here for cost of cpu pause: https://community.intel.com/t5/Intel-ISA-Extensions/Pause-instruction-cost-and-proper-use-in-spin-loops/m-p/1137387
 */

#ifndef ZC_IN_H
#define ZC_IN_H

#include "zc_args.h"

void do_zc_switchless_request(zc_req *request);
void get_zc_switchless_response(unsigned int req_id);
void ZC_REQUEST_WAIT(volatile int *isDone);

#define ZC_PAUSE() __asm__ __volatile__("pause" \
                                        :       \
                                        :       \
                                        : "memory")

#if defined(__cplusplus)
extern "C"
{
#endif

#if defined(__cplusplus)
}
#endif
#endif /* ZC_IN_H */
