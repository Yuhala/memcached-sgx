/*
 * Created on Thu Oct 07 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, Michael Paper IIUN
 * Code for ZC switchless scheduler
 * 
 */

#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <pthread.h>
#include <signal.h>

#include <errno.h>
#include "zc_logger.h"

#include "zc_out.h"
#include "memcached/mpool.h"
#include "zc_ocalls_out.h"

#include "zc_locks.h"
#include "zc_scheduler.h"

#include <unistd.h>
#include <sys/syscall.h>

#define SGX_TCS_NUM 8
#define CORES_NUM 4
#define TIME_ENCLAVE_SWITCH 13500
#define TIME_MICRO_QUANTUM 100000 // 1000000 = 1ms
#define MICRO_INVERSE 100
#define CPU_FREQ 3.8

static int time_before;
static int time_after;
int time_quantum;

int total_sl = 0; /* total # of switchless calls at runtime */
int total_fb = 0; /* total # of fallback calls */

int number_of_useful_schedulings = 0;
//pthread_t workers[CORES_NUM / 2];

extern int num_cores;

// statistics of the switchless run
extern zc_stats *zc_statistics;

extern pthread_t *workers;

extern unsigned int num_workers;

//int number_of_results[CORES_NUM / 2 + 1] = {0};
int *number_of_results;

pthread_t scheduling_thread;

//forward declarations
void *scheduling_thread_fn(void *arg);

void zc_create_scheduling_thread()
{
    /* Creating the scheduling thread */
    int pthread_ret = pthread_create(&scheduling_thread, 0, scheduling_thread_fn, NULL);
    if (pthread_ret != 0)
    {
        fprintf(stderr, "Error: scheduling thread initialization failed\n");
        exit(1);
    }
}

void zc_set_number_of_workers(int m)
{
    //printf("------------- zc-schd setting num of workers to: %d ---------------\n",m);
    int tmp;
    int i;

    if (m > num_workers)
        while (m > num_workers)
        {
            // send signal to worker
            pthread_kill(workers[num_workers++], SIGALRM);
        }

    else
    {
        num_workers = m;
    }
}

int zc_compute_opt_workers(void)
{
    long long argmin, min;
    long long mprime, uchapeau;

    int usize = num_cores / 2 + 1;
    long long *u = (long long *)malloc(sizeof(long long) * usize);
    //long long u[CORES_NUM / 2 + 1];

    //min = number_of_fallbacked_calls*TIME_ENCLAVE_SWITCH + number_of_workers*time_quantum;
    //argmin = number_of_workers;
    //u[argmin] = min;

    min = 100000000000;
    argmin = -1;

    for (mprime = 0; mprime <= num_cores / 2; mprime++)
    {
        //if (mprime != number_of_workers)
        {
            if (num_workers == 0 && mprime == 0)
                uchapeau = zc_statistics->num_zc_fallback_calls * TIME_ENCLAVE_SWITCH;
            else if (num_workers != 0)
                uchapeau = ((zc_statistics->num_zc_fallback_calls + (num_workers - mprime) * (zc_statistics->num_zc_swtless_calls / num_workers)) * TIME_ENCLAVE_SWITCH) + (mprime * time_quantum);
            else
                uchapeau = ((zc_statistics->num_zc_fallback_calls / mprime) * TIME_ENCLAVE_SWITCH) + (mprime * time_quantum);
            u[mprime] = uchapeau;
            if (uchapeau < min)
            {
                min = uchapeau;
                argmin = mprime;
            }
        }
    }

    /*if (number_of_useful_schedulings % 100 == 0 || argmin != number_of_workers)
    {
	printf("Scheduling number %d\n")
	if (argmin != number_of_workers)
	    printf("\t\e[1;31mCHANGEMENT !\e[0m %d -> %d\n", number_of_workers, argmin);
	printf("\t\e[0;33mnumber_of_switchless_calls\e[0m : %d\n", number_of_sl_calls);
	printf("\t\e[0;33mnumber_of_fallbacked_calls\e[0m : %d\n", number_of_fallbacked_calls);
	for (mprime=0; mprime<CORES_NUM/2 + 1; mprime++)
	    if (mprime == argmin)
		printf("\t\e[0;32mÛ_%d = %d\e[0m\n", mprime, u[mprime]);
	    else
		printf("\tÛ_%d = %d\n", mprime, u[mprime]);
    }*/

    free(u);
    return argmin;
}

/* Code of the scheduling thread */
void *scheduling_thread_fn(void *arg)
{
    (void)arg;

    struct sigevent sevp;
    timer_t timerid;
    struct sigaction act;
    struct itimerspec timervalue;
    int next_number_of_workers;
    struct sched_param param;
    int i;
    long long uchapeaumin, uchapeautmp;
    int argmin;

    int sz = num_cores / 2 + 1;
    //long long u[CORES_NUM / 2 + 1], sl[CORES_NUM / 2 + 1], fb[CORES_NUM / 2 + 1];

    long long *u = (long long *)malloc(sizeof(long long) * sz);
    long long *sl = (long long *)malloc(sizeof(long long) * sz);
    long long *fb = (long long *)malloc(sizeof(long long) * sz);

    number_of_results = (int *)calloc(sz, sizeof(int));

    /* setting the scheduling priority to a high priority */
    param.sched_priority = 99;
    if (sched_setscheduler(0, SCHED_FIFO, &param) == -1)
    {
        //perror("Unable to change the policy of the scheduling thread to SCHED_FIFO");
        //exit(1);
        fprintf(stderr, "[\e[0;33mWarning\e[0m] Unable to change the policy of the scheduling thread to SCHED_FIFO\n");
    }
    act.sa_handler = sig_ign;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    if (sigaction(SIGALRM, &act, NULL) != 0)
    {
        perror("Could not set scheduler's timer");
        exit(1);
    }

    sevp.sigev_notify = SIGEV_THREAD_ID;
    sevp._sigev_un._tid = syscall(SYS_gettid);
    sevp.sigev_signo = SIGALRM;
    if (timer_create(CLOCK_REALTIME, &sevp, &timerid) != 0)
    {
        perror("Could not set scheduler's timer");
        exit(1);
    }

    timervalue.it_interval.tv_sec = 0;
    timervalue.it_interval.tv_nsec = TIME_MICRO_QUANTUM;
    timervalue.it_value.tv_sec = 0;
    timervalue.it_value.tv_nsec = TIME_MICRO_QUANTUM;
    if (timer_settime(timerid, 0, &timervalue, NULL) != 0)
    {
        perror("Could not set scheduler's timer");
        exit(1);
    }

    while (1)
    {
        uchapeaumin = 100000000000;
        argmin = -1;
        zc_set_number_of_workers(0);
        zc_reset_runtime_data();
        for (i = 0; i <= num_cores / 2; i++)
        {
            pause();
            /* counting the number of cpu cycles since */
            time_after = rdtscp();
            time_quantum = time_after - time_before;
            time_before = time_after;
            uchapeautmp = zc_statistics->num_zc_fallback_calls * TIME_ENCLAVE_SWITCH + i * time_quantum;
            u[i] = uchapeautmp;
            sl[i] = zc_statistics->num_zc_swtless_calls;
            fb[i] = zc_statistics->num_zc_fallback_calls;
            if (uchapeautmp < uchapeaumin)
            {
                uchapeaumin = uchapeautmp;
                argmin = i;
            }
            if (i < num_cores / 2)
            {
                zc_set_number_of_workers(i + 1);
            }

            //set_number_of_workers(0);
            zc_reset_runtime_data();
        }
        /*if (number_of_useful_schedulings % 5 == 0)
	{
	    printf("Scheduling number %d\n", number_of_useful_schedulings);
	    for (i=0; i<CORES_NUM/2 + 1; i++)
	    {
		if (i == argmin)
		    printf("\t\e[0;32mÛ_%d = %d\e[0m", i, u[i]);
		else
		    printf("\tÛ_%d = %d", i, u[i]);
		printf("\tsl : %d\tfb : %d\n", sl[i], fb[i]);
	    }
	}*/
        next_number_of_workers = argmin;
        number_of_results[next_number_of_workers]++;
        zc_set_number_of_workers(next_number_of_workers);
        for (i = 0; i < MICRO_INVERSE; i++)
        {
            pause();
        }

        number_of_useful_schedulings++;
        /* counting the number of cpu cycles since */
        time_after = rdtscp();
        time_quantum = time_after - time_before;
        time_before = time_after;

        //next_number_of_workers = compute_opt_workers();
        //printf("next number of workers : %d\n", next_number_of_workers);
        //printf("number of calls : %d\n", number_of_sl_calls + number_of_fallbacked_calls);
    }

    //free mem
    free(u);
    free(sl);
    free(fb);
    free(number_of_results);
}

void zc_reset_runtime_data(void)
{

    //account for these b4 re-initializing
    total_sl += __atomic_load_n(&zc_statistics->num_zc_swtless_calls, __ATOMIC_SEQ_CST);
    total_fb += __atomic_load_n(&zc_statistics->num_zc_fallback_calls, __ATOMIC_SEQ_CST);

    //printf("---------------- doing zc reset: SL: %d FB: %d -------------------\n",total_sl,total_fb);

    //re-initialize
    __atomic_store_n(&zc_statistics->num_zc_swtless_calls, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&zc_statistics->num_zc_fallback_calls, 0, __ATOMIC_SEQ_CST);

    //zc_statistics->num_zc_swtless_calls = 0;
    //zc_statistics->num_zc_fallback_calls = 0;
}

void sig_ign(int arg) { (void)arg; }
