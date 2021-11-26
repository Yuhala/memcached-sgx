

/*
 * Created on Mon Nov 22 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#include "kyoto_logger_in.h"
#include "enclave_common.h"

//pyuhala: custom logging
#define KC_LOGGER_IN 1

//#undef KC_LOGGER_IN

void log_kyoto_routine(const char *func)
{
#ifdef KC_LOGGER_IN
    printf("Enclave kyoto function: %s\n", func);
#else
//do nothing: important to avoid needless ocalls when integrating sgx
#endif
}
void log_kyoto_info(const char *msg, const char *func)
{
#ifdef KC_LOGGER_IN
    printf(">>> kyoto info: %s --> %s >>>\n", msg, func);
#else
//do nothing: important to avoid needless ocalls when integrating sgx
#endif
}

void log_kyoto_error(const char *message, const char *func)
{
#ifdef KC_LOGGER_IN
    printf("Enclave kyoto error: %s | : %s\n", message, func);
#else
//do nothing: important to avoid needless ocalls when integrating sgx
#endif
}

void log_kyoto_error(const char *msg1, const char *msg2, const char *func)
{
#ifdef KC_LOGGER_IN
    printf("Enclave kyoto error: %s: | %s | : %s\n", msg1, msg2, func);
#else
//do nothing: important to avoid needless ocalls when integrating sgx
#endif
}
