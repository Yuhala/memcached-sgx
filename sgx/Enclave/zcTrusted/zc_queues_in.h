
/*
 * Created on Wed Sep 29 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#ifndef ZC_QUEUES_IN_H
#define ZC_QUEUES_IN_H

#include "zc_types.h"

void init_zc_queues();
void zc_enq(zc_q_type qt, void *info);
void *zc_dq(zc_q_type qt);
int isempty(zc_q_type qt);
void init_zc_queue_locks();
void init_zc_pool_lock();
void *zc_malloc(size_t siz);
void *zc_malloc(int poolIndex, size_t siz);
void zc_free(void *pOld);
// sgx_thread lock/unlock
void ZC_QUEUE_LOCK(zc_q_type qt);
void ZC_QUEUE_UNLOCK(zc_q_type qt);

void ZC_POOL_LOCK();
void ZC_POOL_UNLOCK();

// lock free mpmc queues
// int zc_newmpmcq(struct mpmcq *q, size_t buffer_size);
int zc_mpmc_enqueue(volatile struct mpmcq *q, void *data);
int zc_mpmc_dequeue(volatile struct mpmcq *q, void **data);
// void init_zc_mpmc_queues();

#endif /* ZC_QUEUES_IN_H */
