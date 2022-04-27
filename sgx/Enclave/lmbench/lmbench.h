/*
 * Created on Wed Apr 27 2022
 *
 * Copyright (c) 2022 Peterson Yuhala
 */

#ifndef B7EF57C2_A8E1_4E2C_86BF_019DE1A98A20
#define B7EF57C2_A8E1_4E2C_86BF_019DE1A98A20

#define BUF_SIZ 1024

typedef struct _state
{
    int fd;
    char *file;    
} _state;

typedef enum
{
    READ_OP = 0, // read request
    WRITE_OP,    // write request
    STAT_OP      // stat request

} op_type;

#if defined(__cplusplus)
extern "C"
{
#endif

    void lmbench_do_read(int num_reads, int thread_id, void *cookie);
    void lmbench_do_write(int num_writes, int thread_id, void *cookie);

#if defined(__cplusplus)
}
#endif

#endif /* B7EF57C2_A8E1_4E2C_86BF_019DE1A98A20 */
