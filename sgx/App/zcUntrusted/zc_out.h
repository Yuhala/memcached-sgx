

/*
 * Created on Wed Sep 29 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#ifndef ZC_OUT_H
#define ZC_OUT_H

#include "zc_args.h"
#include "zc_queues_out.h"

void init_zc(int numWorkers);


#define ZC_RET_OK 1    /* zc call passed */
#define ZC_RET_ERROR 2 /* zc call failed */

#endif /* ZC_OUT_H */