/*
 * Created on Fri Sep 03 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#include <stdio.h>
#define ZC_LOGGING 1
#undef ZC_LOGGING

void log_zc_routine(const char *func)
{
#ifdef ZC_LOGGING
    printf("ZC untrusted function: %s\n", func);
#else
//do nothing
#endif
}