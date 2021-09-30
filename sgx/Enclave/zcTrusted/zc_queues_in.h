
/*
 * Created on Wed Sep 29 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#ifndef ZC_QUEUES_IN_H
#define ZC_QUEUES_IN_H

#include "zc_args.h"

void init_zc_queues();
void zc_enq(zc_q_type qt);
void *zc_dq(zc_q_type qt);
int isempty(zc_q_type qt);
void init_zc_queue_locks();

// sgx_thread lock/unlock
void REQ_LOCK();
void REQ_UNLOCK();
void RESP_LOCK();
void RESP_UNLOCK();

#endif /* ZC_QUEUES_IN_H */
