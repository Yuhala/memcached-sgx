

/*
 * Created on Tue Sep 21 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

//pyuhala: custom logging
#define LOG_FUNC_IN 1

//#undef LOG_FUNC_IN

void log_routine(const char *func)
{
#ifdef LOG_FUNC_IN
    printf("Enclave memcached function: %s\n", func);
#else
//do nothing: important to avoid needless ocalls when integrating sgx
#endif
}
