

/*
 * Created on Mon Nov 22 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#ifndef KYOTO_LOGGER_H
#define KYOTO_LOGGER_H

void log_kyoto_error(const char *msg, const char* func);
void log_kyoto_error(const char* msg1, const char* msg2,const char *func);
void log_kyoto_routine(const char *func);
void log_kyoto_info(const char *msg, const char *func);

#endif /* KYOTO_LOGGER_H */
