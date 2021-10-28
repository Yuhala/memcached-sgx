
/*
 * Created on Thu Oct 25 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#ifndef SCHEDULER_H
#define SCHEDULER_H

#include <stdint.h>

// function prototypes

void zc_create_scheduling_thread();
//initialize scheduler
void init_zc_scheduler();
//reinitize statistics
void reinitialize_stats();

// default freq (in MHz)
#define DEFAULT_CPU_FREQ (3.8 * 1000)

// estimated time for enclave switch in cycles
#define TIME_ENCLAVE_SWITCH 13500

// mu: % of QUANTUM time for micro quantum
#define u 0.75

// scheduler quantum in seconds (10ms --> 0.01)
#define QUANTUM 10

// estimated time for micro quantum
#define MICRO_QUANTUM (u * QUANTUM)

// used to convert MHz to Hz
#define MEGA (1000 * 1000)

// small number for num_fallback calls to avoid division by 0
#define SMALL_NUM 0.000000001

// custom counter for prints
#define COUNTER 1000


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
