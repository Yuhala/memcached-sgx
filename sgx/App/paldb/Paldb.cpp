
/*
 * Created on Fri Aug 27 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#include "Paldb.h"
#include "Enclave_u.h"
#include "sgx_urts.h"

#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>

extern sgx_enclave_id_t global_eid;
extern struct buffer switchless_buffers[];
extern __thread struct buffer *switchless_buffer;
extern volatile sig_atomic_t number_of_sl_calls;
extern volatile sig_atomic_t number_of_fallbacked_calls;
extern volatile sig_atomic_t number_of_workers;
extern void *shim_switchless_functions[];
extern void *shim_functions[];

extern bool use_zc_switchless;

/**
 * Used by the writers. We need to make sure any 2 writers don't use the same 
 * storeId ==> storeFile
 */
static int write_store_counter = 0;
static int read_store_counter = 0;
pthread_mutex_t kissdb_lock;

struct thread_args
{
    int nkeys;
    /*read/writer id*/
    int rw_id;
};

void *reader_thread(void *input)
{
    int n = ((struct thread_args *)input)->nkeys;
    //int id = ((struct thread_args *)input)->rw_id;
    // readers read in the store corresponding to their store id

    //int id = (write_store_counter > 0) ? write_store_counter - 1 : 0;
    int id = __atomic_fetch_add(&read_store_counter, 1, __ATOMIC_RELAXED);
      
    ecall_readKissdb(global_eid, n, id);
}

void *writer_thread(void *input)
{
    int n = ((struct thread_args *)input)->nkeys;
    //int id = ((struct thread_args *)input)->rw_id;

    //pthread_mutex_lock(&lock);
    //id = write_store_counter++;
    int id = __atomic_fetch_add(&write_store_counter, 1, __ATOMIC_RELAXED);
    //pthread_mutex_unlock(&lock);
   
    ecall_writeKissdb(global_eid, n, id);
}

/**
 * Writes nKeys kv pairs in paldb with nThreads
 * The number of kv pairs will be divided among the number of threads more or less evenly.
 */

void write_keys(int nKeys, int nThreads)
{
    struct thread_args *args = (struct thread_args *)malloc(sizeof(struct thread_args));
    /**
     * Roughly divide the number of keys among the threads
     */
    args->nkeys = nKeys / nThreads;
    args->rw_id = 0;
    pthread_t id[nThreads];

    for (int i = 0; i < nThreads; i++)
    {
        pthread_create(&id[i], NULL, writer_thread, (void *)args);
    }
    for (int i = 0; i < nThreads; i++)
    {
        pthread_join(id[i], NULL);
    }
}

/**
 * Reads nKeys kv pairs in paldb with nThreads
 * The number of keys will be divided among the number of threads more or less evenly.
 */

void read_keys(int nKeys, int nThreads)
{
    struct thread_args *args = (struct thread_args *)malloc(sizeof(struct thread_args));
    /**
     * Roughly divide the number of keys among the threads
     */
    args->nkeys = nKeys / nThreads;
    args->rw_id = 0;
    pthread_t id[nThreads];

    for (int i = 0; i < nThreads; i++)
    {
        pthread_create(&id[i], NULL, reader_thread, (void *)args);
        args->rw_id += 1;
    }
    for (int i = 0; i < nThreads; i++)
    {
        pthread_join(id[i], NULL);
    }
}
