/*
 * Created on Mon Sep 06 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#ifndef MEMCACHED_SGX_OUT_H
#define MEMCACHED_SGX_OUT_H

#include "Enclave_u.h"
#include "sgx_urts.h"
#include "my_logger.h"



/**
 * External variables
 */
extern sgx_enclave_id_t global_eid;


#if defined(__cplusplus)
extern "C"
{
#endif

void *e_slab_rebalance_thread(void *);
void * e_item_lru_bump_buf_create(void);
   

#if defined(__cplusplus)
}
#endif

#endif /* MEMCACHED_SGX_OUT_H */
