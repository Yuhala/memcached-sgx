/*
 * Created on Fri Oct 01 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#ifndef ZC_OCALLS_OUT_H
#define ZC_OCALLS_OUT_H

void zc_read_switchless(zc_req *request);
void zc_write_switchless(zc_req *request);
void zc_sendmsg_switchless(zc_req *request);
void zc_fwrite_switchless(zc_req *request);
void zc_fread_switchless(zc_req *request);
void zc_fseeko_switchless(zc_req *request);

#endif /* ZC_OCALLS_OUT_H */
