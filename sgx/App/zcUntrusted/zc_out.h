

/*
 * Created on Wed Sep 29 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#ifndef ZC_OUT_H
#define ZC_OUT_H

#include "zc_types.h"
#include "zc_queues_out.h"

void init_zc(int num_sl_workers);
void handle_zc_switchless_request(zc_req *request, int pool_index);
void finalize_zc();
int get_cpu_freq();
void zc_signal_handler(int sig);

#define ZC_RET_OK 1    /* zc call passed */
#define ZC_RET_ERROR 2 /* zc call failed */

#endif /* ZC_OUT_H */
