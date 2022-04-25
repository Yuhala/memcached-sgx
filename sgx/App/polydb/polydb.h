/*
 * Created on Fri Aug 27 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 *
 */

#ifndef PALDB_H
#define PALDB_H

/**
 * dynamic workload state
 */

typedef enum
{
    INCREASE = 0, // increase request frquency
    CONSTANT,     // constant request frequency
    DECREASE      // decrease request frequency

} workload_state;

// number of possible states
#define NUM_STATES 3

#define MICRO_SECS 1000000

#define RES_FILE_LEN 30

#if defined(__cplusplus)
extern "C"
{
#endif

    void *reader_thread(void *input);
    void *writer_thread(void *input);
    void *writer_thread_dynamic(void *input);
    void write_keys(int num_keys, int num_threads);
    void write_keys_dynamic(int num_keys, int num_threads, double run_time);
    void read_keys(int num_keys, int num_threads);

    double do_request(int num_keys, int thread_id);
    char *create_results_file(int thread_id);

#if defined(__cplusplus)
}
#endif

#endif /* PALDB_H */
