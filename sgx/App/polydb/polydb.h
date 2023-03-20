/*
 * Created on Fri Aug 27 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 *
 */

#ifndef PALDB_H
#define PALDB_H

// number of possible states
#define NUM_STATES 3

#define MICRO_SECS 1000000

#define RES_FILE_LEN 32

#define BUF_SIZ 1024


#include <zc_types.h>

extern int sdk_switchless;
extern int zc_switchless;

extern unsigned int num_workers;
extern zc_stats *zc_statistics;
extern unsigned int num_active_zc_workers;



/**
 * dynamic workload state
 */

typedef enum
{
    INCREASE = 0, // increase request frquency
    CONSTANT,     // constant request frequency
    DECREASE      // decrease request frequency

} workload_state;

typedef enum
{
    READ_OP = 0, // read request
    WRITE_OP,    // write request
    STAT_OP      // stat request

} op_type;

typedef struct _state
{
    int fd;
    char *file;
} _state;

#if defined(__cplusplus)
extern "C"
{
#endif

    void *reader_thread(void *input);
    void *writer_thread(void *input);
    void *bench_thread_dynamic(void *input);

    unsigned int get_num_active_workers();

    _state *get_read_cookie();
    _state *get_write_cookie();

    void wait_for_start();
    void write_bench(int num_ops, int num_threads);
    void read_bench(int num_ops, int num_threads);
    void bench_dynamic(int num_ops, int num_threads, double run_time);

    double do_request(int num_ops, int thread_id, int operation, void *cookie);
    char *create_results_file(int thread_id);

    //lmbench specific
    void *lm_thread(void *input);
    void lmbench_simple(int num_ops, int num_threads);

    //openssl bench
    void *encrypt_thread(void *input);
    void *decrypt_thread(void *input);
    void openssl_bench(int max_bytes);

#if defined(__cplusplus)
}
#endif

#endif /* PALDB_H */
