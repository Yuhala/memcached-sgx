/*
 * Created on Fri Oct 01 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#ifndef ZC_OCALLS_OUT_H
#define ZC_OCALLS_OUT_H

// IO
void zc_read_switchless(zc_req *request);
void zc_write_switchless(zc_req *request);
void zc_fwrite_switchless(zc_req *request);
void zc_fread_switchless(zc_req *request);
void zc_fseeko_switchless(zc_req *request);

int zc_fsync_switchless(zc_req *request);
void zc_sync_switchless(zc_req *request);
int zc_ftruncate64_switchless(zc_req *request);
// NET
void zc_sendmsg_switchless(zc_req *request);
void zc_transmit_prepare(zc_req *request);

//for benchmarking
void zc_test_switchless(zc_req *request);
void zc_f(zc_req *request);
void zc_g(zc_req *request);

#endif /* ZC_OCALLS_OUT_H */
