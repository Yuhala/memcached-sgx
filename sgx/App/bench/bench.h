/*
 * Created on Thu Apr 21 2022
 *
 * Copyright (c) 2022 Peterson Yuhala
 */

#ifndef ADA85AB1_B070_4021_A635_BC51ABB8323E
#define ADA85AB1_B070_4021_A635_BC51ABB8323E

// pyuhala: prototypes for all the bench routines
void run_kissdb_bench(int num_runs);
void runTestMulti(int num_runs);
void run_zc_micro(int num_runs);
void run_kyoto_bench();
void remove_kc_dbs();
void run_kyoto_bench(int num_runs);
void run_zc_fg(int num_runs);

// other prototypes
void print_stack_protector_checks();
// pthread_t scheduling_thread;

/* Initializing the buffers */
void init_switchless(void);
void destroy_switchless(void);

// dynamic benchmarks
void run_kissdb_dynamic(double run_time, int num_runs);

#endif /* ADA85AB1_B070_4021_A635_BC51ABB8323E */
