/*
 * Created on Fri Sep 03 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#include <stdio.h>
#define ZC_LOGGING_IN 1
#undef ZC_LOGGING_IN

void log_zc_routine(const char *func)
{
#ifdef ZC_LOGGING
    printf("ZC trusted function: %s\n", func);
#else
//do nothing
#endif
}