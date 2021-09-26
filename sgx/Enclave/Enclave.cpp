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

#include "Enclave.h"

#include <sgx_spinlock.h>

#include "kissdb/kissdb.h"

// Graal headers
#include "graal_isolate.h"
#include "main.h"
#include <inttypes.h>

// switchless headers
#include "switchless_buffer.h"
#include "graal_sgx_shim_switchless.h"

#include "memcached/test.h"
#include "memcached/memcached.h"




/* Global variables */
sgx_enclave_id_t global_eid;
bool enclave_initiated;
graal_isolatethread_t *global_enc_iso;
struct buffer *switchless_buffers;
__thread struct buffer *switchless_buffer;
void **shim_switchless_functions;
void **shim_functions;
volatile sig_atomic_t *number_of_sl_calls;
volatile sig_atomic_t *number_of_fallbacked_calls;
volatile sig_atomic_t *number_of_workers;
static __thread pid_t global_tid = -1;

SGX_FILE stdin = SGX_STDIN;
SGX_FILE stdout = SGX_STDOUT;
SGX_FILE stderr = SGX_STDERR;

/**
 * For kissdb
 * pyuhala: this global handle causes race issues
 */
//KISSDB writes_db;
static sgx_spinlock_t writer_lock = SGX_SPINLOCK_INITIALIZER;

void readKissdb(int n, int storeId);
void writeKissdb(int n, int storeId);

/**
 * pyuhala: generic ecall for testing enclave routines.
 * E.g after writing a new function you can call it in here
 * to test its functionality.
 */

void ecall_test()
{
    printf("ecall test >>>>>>>>> \n");    
    //start_server();
    //memcached_init();
   
}

pid_t gettid(void)
{
    long tid;
    if (global_tid < 0)
    {
        ocall_gettid(&tid);
        global_tid = (pid_t)tid;
    }
    return global_tid;
}

void test_routine(int);
/* Sends the request for OCALL execution whose details can be found in
 * switchless_buffer to the worker thread and waits the worker thread's signal
 * that the operation is over
 */
void ocall_switchless(struct buffer *switchless_buffer)
{
    switchless_buffer->caller_tid = gettid();
    switchless_buffer->status = BUFFER_WAITING;
    while (switchless_buffer->status != BUFFER_PROCESSED)
    {
    }
}

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

void fill_array()
{
    printf("Filling inside array\n");
    unsigned int size = 1024 * 1024 * 4; //16mb
    int *array = (int *)malloc(sizeof(int) * size);
    int idx = 0;
    for (int i = 0; i < size; i++)
    {
        array[i] = i;
        idx = i;
    }
    printf("Largest index in: %d\n", idx);
}

/* makes 10 million calls to read or write with a buffer of size 0 <= n <=
 * 65536, switchlessly or not (check what `should_be_switchless` returns before
 * using this)
 */
void rw_benchmark(int n)
{
    int i, fdr, fdw;
    ssize_t ret;
    int buf[65536];

    /* read switchless */
    /*if ((fdr = open("/dev/zero", O_RDONLY)) == -1)
	printf("\e[1;31mErreur !\e[0m\n");
    for (i=0; i<100000; i++)
	ret = read(fdr, buf, n);*/
    /* read not switchless */
    if ((fdr = open("/dev/zero", O_RDONLY)) == -1)
        printf("\e[1;31mErreur !\e[0m\n");
    for (i = 0; i < 100000; i++)
        ocall_read(&ret, fdr, buf, n);
    /* write switchless */
    /*if ((fdw = open("/dev/null", O_WRONLY | O_APPEND)) == -1)
	printf("\e[1;31mErreur !\e[0m\n");
    for (i=0; i<100000; i++)
	ret = write(fdw, buf, n);*/
    /* write not switchless */
    /*if ((fdw = open("/dev/null", O_WRONLY | O_APPEND)) == -1)
	printf("\e[1;31mErreur !\e[0m\n");
    for (i=0; i<10000000; i++)
	ocall_write(&ret, fdw, buf, n);*/
}

void ecall_bench_thread(struct buffer *bs, struct buffer *b, void **sl_fn, void **fn, sig_atomic_t *sl_count, sig_atomic_t *f_count, int *workers)
{
    /* initializing global values */
    switchless_buffers = bs;
    switchless_buffer = b;
    shim_switchless_functions = sl_fn;
    shim_functions = fn;
    number_of_sl_calls = sl_count;
    number_of_fallbacked_calls = f_count;
    number_of_workers = workers;
    ssize_t ret;
    int i, fdw;
    int buf[65536];

    if ((fdw = open("/dev/zero", O_WRONLY | O_APPEND)) == -1)
        printf("\e[1;31mErreur !\e[0m\n");
    for (i = 0; i < 100000; i++)
        if (i % 4)
            empty(0);
        else
            empty(5);
    //ret = write(fdw, buf, 8192);
    //ocall_write(&ret, fdw, buf, 0);
}

//run main w/0 args: default
void ecall_graal_main(int id, struct buffer *bs, struct buffer *b, void **sl_fn, void **fn, sig_atomic_t *sl_count, sig_atomic_t *f_count, int *workers)
{
    global_eid = id;
    enclave_initiated = true;
    switchless_buffers = bs;
    switchless_buffer = b;
    shim_switchless_functions = sl_fn;
    shim_functions = fn;
    number_of_sl_calls = sl_count;
    number_of_fallbacked_calls = f_count;
    number_of_workers = workers;
    printf("In ecall_graal_main\n");
    /* small demo */
    /*char buf[2048];
    write(1, "\ntype at least 10 characters then press enter : ", 49);
    read(0, buf, 10);;
    //sleep(3);
    write(1, "what you have typed 3 seconds ago was : ", 40);
    write(1, buf, 10);
    write(1, "\n", 1);*/

    //global_enc_iso = isolate_generator();
    //run_main(1, NULL);
}

//run main with an additional argument
void ecall_graal_main_args(int id, int arg1, struct buffer *bs, struct buffer *b, void **sl_fn, void **fn, int *sl_count, int *f_count, int *workers)
{
    global_eid = id;
    enclave_initiated = true;
    switchless_buffers = bs;
    switchless_buffer = b;
    shim_switchless_functions = sl_fn;
    shim_functions = fn;
    number_of_sl_calls = sl_count;
    number_of_fallbacked_calls = f_count;
    number_of_workers = workers;

    printf("in ecall_graal_main_args\n");
    //rw_benchmark(arg1);
    //ocall_bench();

    //run_main(1, NULL);
    //test_routine(10);
    //int len = _snprintf_s(NULL, 0);

    char str[32];
    snprintf(str, 32, "%d", arg1); //good

    printf("Main argument in enclave %d\n", arg1);
    char *argv[2];
    argv[0] = "run_main";
    argv[1] = str;

    printf("Main arg as string: %s\n", str);

    //run_main(2, argv);
}

void *graal_job(void *arg)
{
    //int sum = graal_add(enc_iso, 1, 2);
    //printf("Enclave Graal add 1+2 = %d\n", sum);

    printf("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx Native Image Code Start xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n");
    //run_main(1, NULL);

    printf("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx  Native Image Code End  xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n");
}

void ecall_run_main(int id)
{
    global_eid = id;
    enclave_initiated = true;
    printf("In ecall run main. Global eid: %d \n", id);
    //run_main(1, NULL);
}

void test_routine(int n)
{
    for (int i = 0; i < n; i++)
    {
        printf("Test routine: %d\n", i);
    }
}

/**
 * Will call graal entry point to read n keys in paldb..
 * A graal isolate is created to serve as execution context for the thread.
 */
void ecall_reader(int n, int id, struct buffer *bs, struct buffer *b, void **sl_fn, void **fn, sig_atomic_t *sl_count, sig_atomic_t *f_count, int *workers)
{
    /* initializing global values */
    switchless_buffers = bs;
    switchless_buffer = b;
    shim_switchless_functions = sl_fn;
    shim_functions = fn;
    number_of_sl_calls = sl_count;
    number_of_fallbacked_calls = f_count;
    number_of_workers = workers;

    //printf("ecall reader: %d keys\n", n);

    //graal_isolatethread_t *iso = isolate_generator();

    readKissdb(n, id);
}

void ecall_set_global_variables(struct buffer *bs, struct buffer *b, void **sl_fn, void **fn, sig_atomic_t *sl_count, sig_atomic_t *f_count, int *workers)
{
    /* initializing global values */
    switchless_buffers = bs;
    switchless_buffer = NULL;
    shim_switchless_functions = sl_fn;
    shim_functions = fn;
    number_of_sl_calls = sl_count;
    number_of_fallbacked_calls = f_count;
    number_of_workers = workers;
}

/**
 * Will call graal entry point to write n kv pairs in paldb
 * A graal isolate is created to serve as execution context for the thread.
 */
void ecall_writer(int n, int id, struct buffer *bs, struct buffer *b, void **sl_fn, void **fn, sig_atomic_t *sl_count, sig_atomic_t *f_count, int *workers)
{
    /* initializing global values */
    switchless_buffers = bs;
    switchless_buffer = b;
    shim_switchless_functions = sl_fn;
    shim_functions = fn;
    number_of_sl_calls = sl_count;
    number_of_fallbacked_calls = f_count;
    number_of_workers = workers;

    //graal_isolatethread_t *iso = isolate_generator();
    //printf("ecall writer: %d keys\n", n);
    writeKissdb(n, id);
}

void ecall_readN(int n)
{

    printf("In ecall readN\n");
    //readN(read_iso, n);
}

void ecall_writeN(int n)
{

    printf("In ecall writeN\n");
    //writeN(write_iso, n);
}

void readKissdb(int n, int storeId)
{
    /**
     * Reading the db should not cause race issues for threads if 
     * all handles are local to the threads
     */
    uint64_t i, j;
    uint64_t v[8];
    KISSDB db;
    char got_all_values[10000];
    int q;

    const char storeFile[16];
    snprintf(storeFile, 16, "kissdb%d.db", storeId);

    printf("ecall_readKissdb::Opening database %s...\n", storeFile);

    if (KISSDB_open(&db, storeFile, KISSDB_OPEN_MODE_RDONLY, 1024, 8, sizeof(v)))
    {
        printf("KISSDB_open failed\n");
    }

    printf("Getting %d 64-byte values in kissdb...\n", n);

    for (i = 0; i < n; ++i)
    {
        if ((q = KISSDB_get(&db, &i, v)))
        {
            printf("KISSDB_get (2) failed (%" PRIu64 ") (%d)\n", i, q);
        }
        for (j = 0; j < 8; ++j)
        {
            if (v[j] != i)
            {
                printf("KISSDB_get (2) failed, bad data (%" PRIu64 ")\n", i);
            }
        }
    }

    printf("Closing database...\n");

    KISSDB_close(&db);
}

void writeKissdb(int n, int storeId)
{
    uint64_t i, j;
    uint64_t v[8];
    //KISSDB db;
    KISSDB writes_db;
    //char got_all_values[10000];
    int q;

    const char storeFile[16];
    snprintf(storeFile, 16, "kissdb%d.db", storeId);

    /**
     * pyuhala - lock the db: multiple threads cannot safely write concurrently to the db as of now
     */

    //sgx_spin_lock(&writer_lock);
    printf("ecall_writeKissdb::Opening new empty database %s...\n", storeFile);

    int retOpen = KISSDB_open(&writes_db, storeFile, KISSDB_OPEN_MODE_RWREPLACE, 1024, 8, sizeof(v));

    if (retOpen)
    {
        printf("KISSDB_open failed\n");
    }

    printf("Adding %d 64-byte kv pairs in kissdb...\n", n);

    for (i = 0; i < n; ++i)
    {
        for (j = 0; j < 8; ++j)
            v[j] = i;
        if (KISSDB_put(&writes_db, &i, v))
        {
            printf("KISSDB_put failed (%" PRIu64 ")\n", i);
        }
        memset(v, 0, sizeof(v));
        if ((q = KISSDB_get(&writes_db, &i, v)))
        {
            printf("KISSDB_get (1) failed (%" PRIu64 ") (%d)\n", i, q);
        }
        for (j = 0; j < 8; ++j)
        {
            if (v[j] != i)
            {
                printf("KISSDB_get (1) failed, bad data (%" PRIu64 ")\n", i);
            }
        }
    }

    printf("Closing database...\n");

    KISSDB_close(&writes_db);

    //sgx_spin_unlock(&writer_lock);
}

void ecall_readKissdb(int n, int storeId)
{
    readKissdb(n, storeId);
}

void ecall_writeKissdb(int n, int storeId)
{
    writeKissdb(n, storeId);
}

void ecall_kissdb_test()
{
    //printf("In ecall kissdb test\n");
    //return;

    uint64_t i, j;
    uint64_t v[8];
    KISSDB_Iterator dbi;
    KISSDB db;
    char got_all_values[10000];
    int q;

    printf("Opening new empty database test.db...\n");

    if (KISSDB_open(&db, "test.db", KISSDB_OPEN_MODE_RWREPLACE, 1024, 8, sizeof(v)))
    {
        printf("KISSDB_open failed\n");
    }

    printf("Adding and then re-getting 10000 64-byte values...\n");

    for (i = 0; i < 10000; ++i)
    {
        for (j = 0; j < 8; ++j)
            v[j] = i;
        if (KISSDB_put(&db, &i, v))
        {
            printf("KISSDB_put failed (%" PRIu64 ")\n", i);
        }
        memset(v, 0, sizeof(v));
        if ((q = KISSDB_get(&db, &i, v)))
        {
            printf("KISSDB_get (1) failed (%" PRIu64 ") (%d)\n", i, q);
        }
        for (j = 0; j < 8; ++j)
        {
            if (v[j] != i)
            {
                printf("KISSDB_get (1) failed, bad data (%" PRIu64 ")\n", i);
            }
        }
    }

    printf("Getting 10000 64-byte values...\n");

    for (i = 0; i < 10000; ++i)
    {
        if ((q = KISSDB_get(&db, &i, v)))
        {
            printf("KISSDB_get (2) failed (%" PRIu64 ") (%d)\n", i, q);
        }
        for (j = 0; j < 8; ++j)
        {
            if (v[j] != i)
            {
                printf("KISSDB_get (2) failed, bad data (%" PRIu64 ")\n", i);
            }
        }
    }

    printf("Closing and re-opening database in read-only mode...\n");

    KISSDB_close(&db);

    if (KISSDB_open(&db, "test.db", KISSDB_OPEN_MODE_RDONLY, 1024, 8, sizeof(v)))
    {
        printf("KISSDB_open failed\n");
    }

    printf("Getting 10000 64-byte values...\n");

    for (i = 0; i < 10000; ++i)
    {
        if ((q = KISSDB_get(&db, &i, v)))
        {
            printf("KISSDB_get (3) failed (%" PRIu64 ") (%d)\n", i, q);
        }
        for (j = 0; j < 8; ++j)
        {
            if (v[j] != i)
            {
                printf("KISSDB_get (3) failed, bad data (%" PRIu64 ")\n", i);
            }
        }
    }

    printf("Iterator test...\n");

    KISSDB_Iterator_init(&db, &dbi);
    i = 0xdeadbeef;
    memset(got_all_values, 0, sizeof(got_all_values));
    while (KISSDB_Iterator_next(&dbi, &i, &v) > 0)
    {
        if (i < 10000)
            got_all_values[i] = 1;
        else
        {
            printf("KISSDB_Iterator_next failed, bad data (%" PRIu64 ")\n", i);
        }
    }
    for (i = 0; i < 10000; ++i)
    {
        if (!got_all_values[i])
        {
            printf("KISSDB_Iterator failed, missing value index %" PRIu64 "\n", i);
        }
    }

    KISSDB_close(&db);

    printf("All tests OK!\n");
}
