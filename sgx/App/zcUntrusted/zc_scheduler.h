
/*
 * Created on Thu Oct 07 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#ifndef ZC_SCHEDULER_H
#define ZC_SCHEDULER_H

#include <stdint.h>

int zc_compute_opt_workers(void);
void zc_set_number_of_workers(int m);
void zc_create_scheduling_thread();
void zc_reset_runtime_data(void);
void sig_ign(int arg);



#ifdef __i386
extern __inline__ uint64_t rdtscp(void)
{
    uint64_t x;
    __asm__ volatile("rdtscp"
                     : "=A"(x));
    return x;
}
#elif defined __amd64
extern __inline__ uint64_t rdtscp(void)
{
    uint64_t a, d;
    __asm__ volatile("rdtscp"
                     : "=a"(a), "=d"(d));
    return (d << 32) | a;
}
#endif

#endif /* ZC_SCHEDULER_H */
