/*
 * Created on Fri Sep 03 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#include <stdio.h>
#define LOG_FUNC 1
#undef LOG_FUNC 

void log_routine(const char *func)
{
#ifdef LOG_FUNC
    printf("Memcached function: %s\n", func);
#else
//do nothing: important to avoid needless ocalls when integrating sgx
#endif
}