

/*
 * =====================================================================================
 *
 *       Filename:  get_cpu_usage.c
 *
 *    Description:  Prints CPU usage percentage in total and for each core
 *
 *        Version:  1.0
 *        Created:  26-12-2016 15:33:29
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  SITKI BURAK CALIM (https://github.com/sbcalim), sburakcalim@gmail.com
 *   Organization:
 *
 * =====================================================================================
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <cmath>

#define PROCSTAT "/proc/stat"
/*
 * ===  FUNCTION  ======================================================================
 *         Name:  get_number_of_cpu_cores
 *  Description:  How many CPU cores are there?
 * =====================================================================================
 */
int get_number_of_cpu_cores()
{
    FILE *fp = fopen(PROCSTAT, "r");

    int n = 0;
    char line[100];

    while (!feof(fp))
    {
        fgets(line, 100, fp);
        if (line[0] == 'c' && line[1] == 'p' && line[2] == 'u')
            n++;
    }
    fclose(fp);

    return n - 1;
} /* -----  end of function get_number_of_cpu_cores  ----- */

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  read_cpu
 *  Description:  Reads /proc/stat file and returns an array[cpu_num][process_type] of process count
 * =====================================================================================
 */
unsigned long long
    **
    read_cpu()
{
    FILE *fp;
    unsigned long long **array;
    char buffer[1024];
    int i, j;
    unsigned long long ignore[6];
    int cpus = get_number_of_cpu_cores();

    array = (unsigned long long **)calloc((cpus + 1), sizeof(unsigned long long));

    fp = fopen(PROCSTAT, "r");
    unsigned long long temp = 0;

    for (i = 0; i < cpus + 1; i++)
    {
        array[i] = (unsigned long long *)calloc(4, sizeof(unsigned long long));
        fscanf(fp, "%*s %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu ",
               &array[i][0], &array[i][1], &array[i][2], &array[i][3],
               &ignore[0], &ignore[1], &ignore[2], &ignore[3], &ignore[4], &ignore[5]);
    }

    fclose(fp);
    return array;
} /* -----  end of function read_cpu  ----- */

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  get_cpu_percentage
 *  Description:  Returns a double value of CPU usage percentage from given array[4] = {USER_PROC, NICE_PROC, SYSTEM_PROC, IDLE_PROC}
 * =====================================================================================
 */
double
get_cpu_percentage(unsigned long long *a1, unsigned long long *a2)
{
    /**
     * pyuhala: below modification from this algorithm
     * https://rosettacode.org/wiki/Linux_CPU_utilization
     */
    // double total_cpu_time = (double)((a1[0] - a2[0]) + (a1[1] - a2[1]) + (a1[2] - a2[2]));
    // double fraction_idle = (double)(a1[3] - a2[3]) / total_cpu_time;
    // double cpu_percent = (double)((1 - fraction_idle) * 100);

    /**
     * pyuhala: check for nan values:
     * if nan value is returned, the a[i][j] probably contains a string,
     * which indicates the core must not be working, and is offline.
     * So in theory it should be at zero percent usage. Src: stackoverflow
     */

    double diff1 = double((a1[0] - a2[0])); //>= 0 ? double((a1[0] - a2[0])) : 0.0;
    double diff2 = double((a1[1] - a2[1])); // >= 0 ? double((a1[1] - a2[1])) : 0.0;
    double diff3 = double((a1[2] - a2[2])); // >= 0 ? double((a1[2] - a2[2])) : 0.0;
    double diff4 = double((a1[3] - a2[3])); // >= 0 ? double((a1[3] - a2[3])) : 0.0;

    // printf("Diff values: dif1: %f  diff2: %f  diff3: %f diff4: %f >>>>>>>>>>>>>>>>\n");

    double denom = (diff1 + diff2 + diff3 + diff4);
    double cpu_percent = (diff1 + diff2 + diff3) / denom;
    cpu_percent *= 100.0;

    return (denom != 0) ? cpu_percent : 0.0;
    //return cpu_percent;

    /* double cpu_percent = (double)(((double)((a1[0] - a2[0]) + (a1[1] - a2[1]) + (a1[2] - a2[2])) /
                                   (double)((a1[0] - a2[0]) + (a1[1] - a2[1]) + (a1[2] - a2[2]) + (a1[3] - a2[3]))) *
                                  100); */

    // printf(">>>>>>>>>>>>>>>>> get_cpu_percentage is: %f >>>>>>>>>>>>>>>>>>\n", cpu_percent);
    // return cpu_percent;

} /* -----  end of function get_cpu_percentage  ----- */

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  main
 *  Description:  Get two results between /proc/stat values and print usage percentage
 * =====================================================================================
 */
int cpu_usage_test()
{
    int i, num_of_cpus = get_number_of_cpu_cores();
    double *percentage;

    printf("CPU");
    for (i = 1; i <= num_of_cpus; i++)
    {
        printf("\tCPU-%d", i);
    }
    printf("\n");

    while (1)
    {
        unsigned long long **p_cpu_array = read_cpu();
        sleep(1);
        unsigned long long **n_cpu_array = read_cpu();

        for (i = 0; i <= num_of_cpus; i++)
        {
            printf("%.2lf\t", get_cpu_percentage(n_cpu_array[i], p_cpu_array[i]));
        }
        printf("\n");

        for (i = 0; i < num_of_cpus; i++)
        {
            free(p_cpu_array[i]);
            free(n_cpu_array[i]);
        }
    }

    return EXIT_SUCCESS;
} /* ----------  end of function main  ---------- */

/**
 * Get average cpu usage for all cpus
 */

double get_avg_cpu_usage(unsigned long long **stop, unsigned long long **start)
{
    int i;
    int num_of_cpus = get_number_of_cpu_cores();

    double total_percentage = 0;

    for (i = 0; i < num_of_cpus; i++)
    {
        total_percentage += get_cpu_percentage(stop[i], start[i]);
    }

    double avg_usage = total_percentage / (double)num_of_cpus;
    return avg_usage;
}