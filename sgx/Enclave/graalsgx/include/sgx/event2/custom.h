/*
 * Created on Tue Sep 14 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * Custom types to prevent compilation errors
 */

#ifndef CUSTOM_H
#define CUSTOM_H

/**
 * pyuhala: redefinition of struct timeval.
 * compiler cannot find it somehow
 */
struct s_timeval
{
  long tv_sec;		/* Seconds.  */
  long int tv_usec;	/* Microseconds.  */
};
#endif /* CUSTOM_H */
