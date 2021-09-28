/*
 * Created on Fri Jul 17 2020
 *
 * Copyright (c) 2020 Peterson Yuhala, IIUN
 */

/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <sys/time.h>
#define MAX_PATH FILENAME_MAX

#include <sys/types.h>
#include <sys/socket.h>

#include "graalsgx/net/graal_net.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/sysinfo.h>
#include <cassert>
#define assertm(exp, msg) assert(((void)msg, exp))

//#define ____sigset_t_defined
#define __iovec_defined 1

#include "Enclave_u.h"
#include "sgx_urts.h"

#include <sgx_spinlock.h>

#include "App.h"
#include "error/error.h"

// Graal headers
#include "graal_isolate.h"
#include "main.h"
#include "user_types.h"

// switchless headers
#include "switchless_buffer.h"
#include <sched.h>
#include <sys/syscall.h>

/* Signal handlers */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <map>
#include "ocall_logger.h"

#include "graal_sgx_shim_switchless_u.h"

//paldb benchmarking
#include "paldb/Paldb.h"

//intel sdk switchless lib
#include <sgx_uswitchless.h>

//for get_nprocs()
#include <sys/sysinfo.h>

/* Benchmarking */
#include "bench/benchtools.h"
#include <time.h>
struct timespec start, stop;
double diff;
using namespace std;
extern std::map<pthread_t, pthread_attr_t *> attr_map;

/* Macro for this value which is in the config file of the enclave because I
 * don't know how to do better
 */
// pyuhala: these should be fixed b/c they are machine dependent; try using
// global variables instead, which you can set to the right values at the start of the program
// for example: num of cores can be obtained with get_nprocs()

#define SGX_TCS_NUM 8
#define CORES_NUM 4
#define TIME_ENCLAVE_SWITCH 13500
#define TIME_MICRO_QUANTUM 100000 // 1000000 = 1ms
#define MICRO_INVERSE 100
#define CPU_FREQ 3.8

static int time_before;
static int time_after;
static int time_quantum;

/* arguments of the worker threads */
struct worker_args
{
    struct buffer *buffer;
    int worker_id;
};

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
/* Corresponding global buffers */
struct buffer switchless_buffers[CORES_NUM / 2];
/* runtime stats */
volatile sig_atomic_t number_of_sl_calls = 0;
volatile sig_atomic_t number_of_fallbacked_calls = 0;
volatile sig_atomic_t number_of_workers = 0;
int number_of_useful_schedulings = 0;
pthread_t workers[CORES_NUM / 2];

/* pointers to the functions of the switchless shim library so that the enclave
 * may use them
 */
void *shim_switchless_functions[] =
    {
        (void *)ocall_empty_switchless,                     /* FN_TOKEN_EMPTY */
        (void *)ocall_ret_int_args_int_switchless,          /* FN_TOKEN_SLEEP */
        (void *)ocall_ret_int_args_int_switchless,          /* FN_TOKEN_FSYNC */
        (void *)ocall_ret_int_args_int_int_switchless,      /* TN_TOKEN_DUP2 */
        (void *)ocall_ret_int_args_int_switchless,          /* FN_TOKEN_CLOSE */
        (void *)ocall_fwrite_switchless,                    /* FN_TOKEN_FWRITE */
        (void *)ocall_fread_switchless,                     /* FN_TOKEN_FREAD */
        (void *)ocall_ret_int_args_const_string_switchless, /* FN_TOKEN_PUTS */
        (void *)ocall_ret_int_args_const_string_switchless, /* FN_TOKEN_UNLINK */
        (void *)ocall_ret_int_args_const_string_switchless, /* FN_TOKEN_RMDIR */
        //(void *)ocall_ret_int_args_const_string_switchless, /* FN_TOKEN_REMOVE */
        (void *)ocall_read_switchless,             /* FN_TOKEN_READ  */
        (void *)ocall_write_switchless,            /* FN_TOKEN_WRITE */
        (void *)ocall_lseek64_switchless,          /* FN_TOKEN_LSEEK64 */
        (void *)ocall_sendmsg_switchless,          /* FN_TOKEN_SENDMSG */
        (void *)ocall_transmit_prepare_switchless, /* FN_TOKEN_TRANSMIT_PREPARE */
};

void empty(void) {}

void *shim_functions[] =
    {
        (void *)empty,  /* FN_TOKEN_EMPTY            */
        (void *)sleep,  /* FN_TOKEN_SLEEP            */
        (void *)fsync,  /* FN_TOKEN_FSYNC            */
        (void *)dup2,   /* FN_TOKEN_DUP2             */
        (void *)close,  /* FN_TOKEN_CLOSE            */
        (void *)fwrite, /* FN_TOKEN_FWRITE           */
        (void *)fread,  /* FN_TOKEN_FREAD            */
        (void *)puts,   /* FN_TOKEN_PUTS             */
        (void *)unlink, /* FN_TOKEN_UNLINK           */
        (void *)rmdir,  /* FN_TOKEN_RMDIR            */
        //(void *)remove,           /* FN_TOKEN_REMOVE           */
        (void *)read,             /* FN_TOKEN_READ             */
        (void *)write,            /* FN_TOKEN_WRITE            */
        (void *)lseek64,          /* FN_TOKEN_LSEEK64          */
        (void *)sendmsg,          /* FN_TOKEN_SENDMSG          */
        (void *)transmit_prepare, /* FN_TOKEN_TRANSMIT_PREPARE */
};

/* Main app isolate */
graal_isolatethread_t *global_app_iso;
/*Main thread id*/
//std::thread::id main_thread_id = std::this_thread::get_id();
pthread_t main_thread_id;

/* Ocall counter */
unsigned int ocall_count = 0;
std::map<std::string, int> ocall_map;

//pyuhala: for intel sdk switchless calls
#define SL_DEFAULT_FALLBACK_RETRIES 20000

void gen_sighandler(int sig, siginfo_t *si, void *arg)
{
    printf("Caught signal: %d\n", sig);
}

void fill_array()
{
    printf("Filling outside array\n");
    unsigned int size = 1024 * 1024 * 4; //16mb
    int *array = (int *)malloc(sizeof(int) * size);
    int idx = 0;
    for (int i = 0; i < size; i++)
    {
        array[i] = i;
        idx = i;
    }
    printf("Largest index is %d\n", idx);
}

int getCpus()
{
    int ret = get_nprocs();
    printf("Number of cores: %d\n", ret);
    return ret;
}

/**
 * Set main thread attribs
 */
void setMainAttribs()
{
    main_thread_id = pthread_self();
    pthread_attr_t *attr = (pthread_attr_t *)malloc(sizeof(pthread_attr_t));
    int ret = pthread_getattr_np(main_thread_id, attr);
    attr_map.insert(pair<pthread_t, pthread_attr_t *>(main_thread_id, attr));
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave_no_switchless(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(const sgx_uswitchless_config_t *us_config)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    const void *enclave_ex_p[32] = {0};

    enclave_ex_p[SGX_CREATE_ENCLAVE_EX_SWITCHLESS_BIT_IDX] = (const void *)us_config;

    ret = sgx_create_enclave_ex(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL, SGX_CREATE_ENCLAVE_EX_SWITCHLESS, enclave_ex_p);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

static inline void _mm_pause(void) __attribute__((always_inline));
static inline int _InterlockedExchange(int volatile *dst, int val) __attribute__((always_inline));

static inline void _mm_pause(void) { __asm __volatile("pause"); }

static inline int _InterlockedExchange(int volatile *dst, int val)
{
    int res;

    __asm __volatile(
        "lock xchg %2, %1;"
        "mov %2, %0"
        : "=m"(res)
        : "m"(*dst),
          "r"(val)
        : "memory");

    return (res);
}

static __thread int sl_calls_treated;

/* Code of the worker thread */
void *worker_thread_fn(void *arg)
{
    struct worker_args *args = (struct worker_args *)arg;
    struct buffer *buffer = args->buffer;
    int worker_id = args->worker_id;
    struct sched_param param;

    /* setting the worker's priority to a high priority */
    param.sched_priority = 50;
    if (sched_setscheduler(0, SCHED_RR, &param) == -1)
    {
        //perror("Unable to change the policy of a worker thread to SCHED_RR");
        //exit(1);
    }

    while (buffer->status != BUFFER_EXIT)
    {
        if (buffer->status == BUFFER_WAITING)
        {
            sl_calls_treated++;
            ((void (*)(struct buffer *))buffer->ocall_handler_switchless)(buffer);
            buffer->status = BUFFER_PROCESSED;
        }
        else if (worker_id >= number_of_workers && buffer->status == BUFFER_UNUSED)
        {
            //sgx_spin_lock(&buffer->spinlock);
            while (_InterlockedExchange((volatile int *)&buffer->spinlock, 1) != 0)
            {
                while (buffer->spinlock)
                {
                    _mm_pause();
                }
            }
            if (worker_id >= number_of_workers && buffer->status == BUFFER_UNUSED)
            {
                buffer->status = BUFFER_PAUSED;
                // sgx_spin_unlock(&buffer->spinlock);
                buffer->spinlock = 0;
                pause();
                if (buffer->status == BUFFER_PAUSED)
                    buffer->status = BUFFER_UNUSED;
            }
            else
                // sgx_spin_unlock(&buffer->spinlock);
                buffer->spinlock = 0;
        }
    }
    printf("\e[0;31mnumber of switchless calls treated by worker %d : %d\e[0m\n", worker_id, sl_calls_treated);
    return NULL;
}

void reset_runtime_data(void)
{
    number_of_sl_calls = 0;
    number_of_fallbacked_calls = 0;
}

void set_number_of_workers(int m)
{
    int tmp;
    int i;

    if (m > number_of_workers)
        while (m > number_of_workers)
            pthread_kill(workers[number_of_workers++], SIGALRM);
    else
        number_of_workers = m;
}

int compute_opt_workers(void)
{
    long long argmin, min;
    long long mprime, uchapeau;
    long long u[CORES_NUM / 2 + 1];

    //min = number_of_fallbacked_calls*TIME_ENCLAVE_SWITCH + number_of_workers*time_quantum;
    //argmin = number_of_workers;
    //u[argmin] = min;

    min = 100000000000;
    argmin = -1;

    for (mprime = 0; mprime <= CORES_NUM / 2; mprime++)
    {
        //if (mprime != number_of_workers)
        {
            if (number_of_workers == 0 && mprime == 0)
                uchapeau = number_of_fallbacked_calls * TIME_ENCLAVE_SWITCH;
            else if (number_of_workers != 0)
                uchapeau = ((number_of_fallbacked_calls + (number_of_workers - mprime) * (number_of_sl_calls / number_of_workers)) * TIME_ENCLAVE_SWITCH) + (mprime * time_quantum);
            else
                uchapeau = ((number_of_fallbacked_calls / mprime) * TIME_ENCLAVE_SWITCH) + (mprime * time_quantum);
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

    return argmin;
}

void sig_ign(int arg) { (void)arg; }

int number_of_results[CORES_NUM / 2 + 1] = {0};

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
    long long u[CORES_NUM / 2 + 1], sl[CORES_NUM / 2 + 1], fb[CORES_NUM / 2 + 1];

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
        set_number_of_workers(0);
        reset_runtime_data();
        for (i = 0; i <= CORES_NUM / 2; i++)
        {
            pause();
            /* counting the number of cpu cycles since */
            time_after = rdtscp();
            time_quantum = time_after - time_before;
            time_before = time_after;
            uchapeautmp = number_of_fallbacked_calls * TIME_ENCLAVE_SWITCH + i * time_quantum;
            u[i] = uchapeautmp;
            sl[i] = number_of_sl_calls;
            fb[i] = number_of_fallbacked_calls;
            if (uchapeautmp < uchapeaumin)
            {
                uchapeaumin = uchapeautmp;
                argmin = i;
            }
            if (i < CORES_NUM / 2)
                set_number_of_workers(i + 1);
            //set_number_of_workers(0);
            reset_runtime_data();
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
        set_number_of_workers(next_number_of_workers);
        for (i = 0; i < MICRO_INVERSE; i++)
            pause();
        number_of_useful_schedulings++;
        /* counting the number of cpu cycles since */
        time_after = rdtscp();
        time_quantum = time_after - time_before;
        time_before = time_after;

        //next_number_of_workers = compute_opt_workers();
        //printf("next number of workers : %d\n", next_number_of_workers);
        //printf("number of calls : %d\n", number_of_sl_calls + number_of_fallbacked_calls);
    }
}

/* Code of a benchmarking thread */
void *enclave_bench_thread(void *arg)
{
    size_t i = *((size_t *)arg);
    ecall_bench_thread(global_eid, switchless_buffers, &switchless_buffers[i % (CORES_NUM / 2)], shim_switchless_functions, shim_functions, (int *)&number_of_sl_calls, (int *)&number_of_fallbacked_calls, (int *)&number_of_workers);
    return NULL;
}

/* Code of gettid for an enclave thread */
long ocall_gettid(void)
{
    pid_t ret;
    ret = syscall(SYS_gettid);
    return ret;
}

/* Code of the benchmark */
void ocall_bench(void)
{
    size_t i;
    pthread_t threads[SGX_TCS_NUM];
    size_t args[SGX_TCS_NUM];
    struct sched_param param;

    /* setting the thread's priority to a high priority */
    /*param.sched_priority = 1;
    if (sched_setscheduler(0, SCHED_RR, &param) == -1)
    {
	perror("Unable to change the policy of a worker thread to SCHED_RR");
	exit(1);
    }*/

    for (i = 0; i < SGX_TCS_NUM; i++)
        args[i] = i;
    for (i = 0; i < SGX_TCS_NUM; i++)
        if (pthread_create(&threads[i], NULL, enclave_bench_thread, &args[i]) != 0)
        {
            fprintf(stderr, "Error creating bench thread number %d, exiting\n", i);
            exit(1);
        }
    for (i = 0; i < SGX_TCS_NUM; i++)
        if (pthread_join(threads[i], NULL) != 0)
        {
            fprintf(stderr, "Error joining bench thread number %d, exiting\n", i);
            exit(1);
        }
}

/**
 * Initialize and launch enclave w/o all the switchless stuff
 * Pyuhala
 */

int normal_run(int arg)
{

    setMainAttribs();

    attr_map.insert(pair<pthread_t, pthread_attr_t *>(0, NULL));
    /* Initialize the enclave */

    if (initialize_enclave_no_switchless() < 0)
    {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }
    printf("Enclave initialized\n");

    int id = global_eid;
    ecall_run_main(global_eid, id);

    printf("Number of ocalls: %d\n", ocall_count);
    showOcallLog(50);

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    return 0;
}

pthread_t scheduling_thread;

/* Initializing the buffers */
void init_switchless(void)
{
    int pthread_ret;
    int i;
    //get the number of logical cpus on the machine
    //int ncores = get_nprocs();
    //int half_cpu = ncores / 2;
    struct worker_args wa[CORES_NUM / 2];
    //struct worker_args *wa = malloc(sizeof(worker_args) * half_cpu);
    //pyuhala: above should be free somewhere..causes memory leak

    int ncores = CORES_NUM;
    //ncores = getCpus();

    for (i = 0; i < ncores / 2; i++)
        if (init_switchless_buffer(&switchless_buffers[i]) != 0)
        {
            fprintf(stderr, "Error: unable to allocate memory for the buffer\n");
            exit(1);
        }

    /* creating the worker threads */
    for (i = 0; i < ncores / 2; i++)
    {
        wa[i].buffer = &switchless_buffers[i];
        wa[i].worker_id = i;
    }
    for (i = 0; i < ncores / 2; i++)
    {
        if (pthread_create(&workers[i], 0, worker_thread_fn, &wa[i]) != 0)
        {
            fprintf(stderr, "Error creating worker thread number %d, exiting\n", i);
            exit(1);
        }
    }

    /* Creating the scheduling thread */
    pthread_ret = pthread_create(&scheduling_thread, 0, scheduling_thread_fn, NULL);
    if (pthread_ret != 0)
    {
        fprintf(stderr, "Error: scheduling thread initialization failed\n");
        exit(1);
    }
}

void destroy_switchless(void)
{
    int i;
    int ncores = get_nprocs();
    //ncores = getCpus();

    /* joining the workers */
    printf("number of useful schedulings : %d\n", number_of_useful_schedulings);
    printf("time_quantum : %d\n", time_quantum);
    for (i = 0; i < ncores / 2 + 1; i++)
        printf("number of %ds : %d\n", i, number_of_results[i]);
    number_of_workers = ncores / 2;
    for (i = 0; i < ncores / 2; i++)
    {
        switchless_buffers[i].status = BUFFER_EXIT;
        pthread_kill(workers[i], SIGALRM);
        if (pthread_join(workers[i], NULL) != 0)
        {
            fprintf(stderr, "Error joining worker thread number %d, exiting\n", i);
            exit(1);
        }
    }

    /* Freeing the allocated memory */
    for (i = 0; i < ncores / 2; i++)
    {
        free(switchless_buffers[i].args);
        free(switchless_buffers[i].ret);
    }
}

void removeKissDbs()
{
    printf(">>>>>>>>>>>>>>..removing kissdb files..>>>>>>>>>>>>>>>>>\n");
    system("rm kissdb*");
}
void runKissdbBench()
{
    int min_keys = 2000;
    int max_keys = 50000;
    int step = 2000;
    int numWriters = 2;
    int numReaders = 2;
    //write_keys(numKeys, numWriters);
    bool test = (numReaders == numWriters) || ((numReaders != numWriters) && (numWriters == 1));
    if (!test)
    {
        printf("xxxxxxxxxxxxxxxx check num of writer and reader threads xxxxxxxxxxxxxxxxxxxx");
        return;
    }

    for (int i = min_keys; i <= max_keys; i += step)
    {
        printf("<--------------------- running kissdb bench for: %d keys ----------------------->\n", i);
        start_clock();
        write_keys(i, numWriters);
        read_keys(i, numReaders);
        stop_clock();
        double runTime = time_diff(&start, &stop, SEC);
        registerKissResults(i, runTime);
        removeKissDbs();
    }
}

/* Application entry */
int main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    int i;
    struct timeval tval_before, tval_after, tval_result;

    int num_mcd_workers = 2;
    int sdk_switchless = 0;
    int zc_switchless = 0;
    int ret_zero = 1;
    if (argc == 3)
    {

        zc_switchless = atoi(argv[1]);
        sdk_switchless = atoi(argv[2]);
    }

    //int ret = normal_run(arg1);
    //return ret;

    setMainAttribs();

    attr_map.insert(pair<pthread_t, pthread_attr_t *>(0, NULL));

    /**
     * Intel SDK switchless configuration
     */

    sgx_uswitchless_config_t us_config = SGX_USWITCHLESS_CONFIG_INITIALIZER;

    if (zc_switchless && sdk_switchless)
    {
        printf("xxxxxxxxxxxxxxx cannot activate both SDK and ZC switchless at the same time xxxxxxxxxxxxxxxxxx\n");
        printf("usage: ./memcached-sgx [zc_switchless] [sdk_switchless]\n");
        return 0;
    }

    /**
     * ZC-switchless configuration
     */

    if (zc_switchless)
    {
        ret_zero = 0;
        init_switchless();
    }

    /* Initialize the enclave */

    if (!sdk_switchless)
    {
        //do not use switchless
        if (initialize_enclave_no_switchless() < 0)
        {
            printf("Enter a character before exit ...\n");
            getchar();
            return -1;
        }
    }
    else
    {
        //use intel sdk switchless
        printf("########################## running in INTEL-SDK-SWITCHLESS mode ##########################");
        us_config.num_uworkers = 2;
        //pyuhala: we are not concerned with switchless ecalls so no trusted workers
        us_config.num_tworkers = 0;
        if (initialize_enclave(&us_config) < 0)
        {
            printf("Enter a character before exit ...\n");
            getchar();
            return -1;
        }
    }

    printf("Enclave initialized\n");
    if (zc_switchless)
    {
        printf("########################## running in ZC-SWITCHLESS mode ##########################");

        if (ecall_set_global_variables(global_eid, switchless_buffers, &switchless_buffers[0], shim_switchless_functions, shim_functions, (int *)&number_of_sl_calls, (int *)&number_of_fallbacked_calls, (int *)&number_of_workers, ret_zero) != SGX_SUCCESS)
        {
            fprintf(stderr, "unable to set global untrusted variables inside the enclave\n");
            exit(1);
        }

        printf("global untrusted variables set inside the enclave\n");
    }

    int id = global_eid;

    //init_memcached(num_mcd_workers);
    //return 0;

    //ecall_create_enclave_isolate(global_eid);
    /**
     * Read/Write n kv pairs in paldb with m threads
     * PYuhala
     */

    runKissdbBench();

    return 0;
    /**
     * pyuhala: this prevents read errors in kissdb (eg readers reading from a non-existent file).
     *  Still to fix the issue
     */
    //assertm(test, "num of reader threads should be = num of writer threads or have only 1 writer thread ");
    //read_keys(numKeys, numReaders);

    //ecall_kissdb_test(global_eid);

    showOcallLog(10);

    return 0;

    /*  if (argc > 1)
    {
        gettimeofday(&tval_before, NULL);
        number_of_useful_schedulings = 0;
        ecall_graal_main_args(global_eid, id, arg1, switchless_buffers, &switchless_buffers[0], shim_switchless_functions, shim_functions, (int *)&number_of_sl_calls, (int *)&number_of_fallbacked_calls, (int *)&number_of_workers);
        gettimeofday(&tval_after, NULL);
        timersub(&tval_after, &tval_before, &tval_result);
        printf("Time elapsed: %ld.%06ld seconds\n", (long int)tval_result.tv_sec, (long int)tval_result.tv_usec);
    }
    else
    {
        ecall_graal_main(global_eid, id, switchless_buffers, &switchless_buffers[0], shim_switchless_functions, shim_functions, (int *)&number_of_sl_calls, (int *)&number_of_fallbacked_calls, (int *)&number_of_workers);
    }
 */
    //ecall_graal_main_args(global_eid, id, arg1);
    /**
     * Invoke main routine of java application: for partitioned apps. 
     * This is the initial entrypoint method, all further ecalls are performed there.
     */

    //run_main(argc, argv);

    if (zc_switchless)
    {
        destroy_switchless();
    }

    printf("Number of ocalls: %d\n", ocall_count);
    showOcallLog(10);

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    /*  printf("Time inside: %lf\n", in);
    printf("Time outside: %lf\n", out); */

    //printf("Enter a character before exit ...\n");
    //getchar();
    return 0;
}
