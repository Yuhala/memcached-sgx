#ifndef CPU_USAGE_H
#define CPU_USAGE_H

int get_number_of_cpu_cores();
unsigned long long **read_cpu();
double get_cpu_percentage(unsigned long long *a1, unsigned long long *a2);
double get_avg_cpu_usage(unsigned long long **stop, unsigned long long **start);

int cpu_usage_test();

#endif /* CPU_USAGE_H */
