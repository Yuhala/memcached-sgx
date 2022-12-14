/* Bit values & structures for resource limits.  Linux version.
   Copyright (C) 1994-2014 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#ifndef _SYS_RESOURCE_H
#error "Never use <bits/resource.h> directly; include <sys/resource.h> instead."
#endif

#include <sgx/bits/types.h>

/* Transmute defines to enumerations.  The macro re-definitions are
   necessary because some programs want to test for operating system
   features with #ifdef RUSAGE_SELF.  In ISO C the reflexive
   definition is a no-op.  */

/* Kinds of resource limit.  */
enum __rlimit_resource
{
  /* Per-process CPU limit, in seconds.  */
  RLIMIT_CPU = 0,
#define RLIMIT_CPU RLIMIT_CPU

  /* Largest file that can be created, in bytes.  */
  RLIMIT_FSIZE = 1,
#define RLIMIT_FSIZE RLIMIT_FSIZE

  /* Maximum size of data segment, in bytes.  */
  RLIMIT_DATA = 2,
#define RLIMIT_DATA RLIMIT_DATA

  /* Maximum size of stack segment, in bytes.  */
  RLIMIT_STACK = 3,
#define RLIMIT_STACK RLIMIT_STACK

  /* Largest core file that can be created, in bytes.  */
  RLIMIT_CORE = 4,
#define RLIMIT_CORE RLIMIT_CORE

  /* Largest resident set size, in bytes.
     This affects swapping; processes that are exceeding their
     resident set size will be more likely to have physical memory
     taken from them.  */
  __RLIMIT_RSS = 5,
#define RLIMIT_RSS __RLIMIT_RSS

  /* Number of open files.  */
  RLIMIT_NOFILE = 7,
  __RLIMIT_OFILE = RLIMIT_NOFILE, /* BSD name for same.  */
#define RLIMIT_NOFILE RLIMIT_NOFILE
#define RLIMIT_OFILE __RLIMIT_OFILE

  /* Address space limit.  */
  RLIMIT_AS = 9,
#define RLIMIT_AS RLIMIT_AS

  /* Number of processes.  */
  __RLIMIT_NPROC = 6,
#define RLIMIT_NPROC __RLIMIT_NPROC

  /* Locked-in-memory address space.  */
  __RLIMIT_MEMLOCK = 8,
#define RLIMIT_MEMLOCK __RLIMIT_MEMLOCK

  /* Maximum number of file locks.  */
  __RLIMIT_LOCKS = 10,
#define RLIMIT_LOCKS __RLIMIT_LOCKS

  /* Maximum number of pending signals.  */
  __RLIMIT_SIGPENDING = 11,
#define RLIMIT_SIGPENDING __RLIMIT_SIGPENDING

  /* Maximum bytes in POSIX message queues.  */
  __RLIMIT_MSGQUEUE = 12,
#define RLIMIT_MSGQUEUE __RLIMIT_MSGQUEUE

  /* Maximum nice priority allowed to raise to.
     Nice levels 19 .. -20 correspond to 0 .. 39
     values of this resource limit.  */
  __RLIMIT_NICE = 13,
#define RLIMIT_NICE __RLIMIT_NICE

  /* Maximum realtime priority allowed for non-priviledged
     processes.  */
  __RLIMIT_RTPRIO = 14,
#define RLIMIT_RTPRIO __RLIMIT_RTPRIO

  /* Maximum CPU time in ??s that a process scheduled under a real-time
     scheduling policy may consume without making a blocking system
     call before being forcibly descheduled.  */
  __RLIMIT_RTTIME = 15,
#define RLIMIT_RTTIME __RLIMIT_RTTIME

  __RLIMIT_NLIMITS = 16,
  __RLIM_NLIMITS = __RLIMIT_NLIMITS
#define RLIMIT_NLIMITS __RLIMIT_NLIMITS
#define RLIM_NLIMITS __RLIM_NLIMITS
};

/* Value to indicate that there is no limit.  */
#ifndef __USE_FILE_OFFSET64
#define RLIM_INFINITY ((__rlim_t)-1)
#else
#define RLIM_INFINITY 0xffffffffffffffffuLL
#endif

#ifdef __USE_LARGEFILE64
#define RLIM64_INFINITY 0xffffffffffffffffuLL
#endif

/* We can represent all limits.  */
#define RLIM_SAVED_MAX RLIM_INFINITY
#define RLIM_SAVED_CUR RLIM_INFINITY

/* Type for resource quantity measurement.  */
#ifndef __USE_FILE_OFFSET64
typedef __rlim_t rlim_t;
#else
typedef __rlim64_t rlim_t;
#endif
#ifdef __USE_LARGEFILE64
typedef __rlim64_t rlim64_t;
#endif

struct rlimit
{
  /* The current (soft) limit.  */
  rlim_t rlim_cur;
  /* The hard limit.  */
  rlim_t rlim_max;
};

#ifdef __USE_LARGEFILE64
struct rlimit64
{
  /* The current (soft) limit.  */
  rlim64_t rlim_cur;
  /* The hard limit.  */
  rlim64_t rlim_max;
};
#endif

/* Whose usage statistics do you want?  */
enum __rusage_who
{
  /* The calling process.  */
  RUSAGE_SELF = 0,
#define RUSAGE_SELF RUSAGE_SELF

  /* All of its terminated child processes.  */
  RUSAGE_CHILDREN = -1
#define RUSAGE_CHILDREN RUSAGE_CHILDREN

#ifdef __USE_GNU
  ,
  /* The calling thread.  */
  RUSAGE_THREAD = 1
#define RUSAGE_THREAD RUSAGE_THREAD
/* Name for the same functionality on Solaris.  */
#define RUSAGE_LWP RUSAGE_THREAD
#endif
};

#define __need_timeval
#include <struct/sgx_time_struct.h> /* For `struct timeval'.  */

#ifndef _STRUCT_TIMEVAL
#define _STRUCT_TIMEVAL 1
#ifndef __timeval_defined
#define __timeval_defined 1
struct timeval
{
  time_t tv_sec;
  long int tv_usec;
};
#endif
#endif
/* Structure which says how much of each resource has been used.  */

/* The purpose of all the unions is to have the kernel-compatible layout
   while keeping the API type as 'long int', and among machines where
   __syscall_slong_t is not 'long int', this only does the right thing
   for little-endian ones, like x32.  */
struct rusage
{
  /* Total amount of user time used.  */
  struct timeval ru_utime;
  /* Total amount of system time used.  */
  struct timeval ru_stime;
  /* Maximum resident set size (in kilobytes).  */
  __extension__ union {
    long int ru_maxrss;
    __syscall_slong_t __ru_maxrss_word;
  };
  /* Amount of sharing of text segment memory
       with other processes (kilobyte-seconds).  */
  /* Maximum resident set size (in kilobytes).  */
  __extension__ union {
    long int ru_ixrss;
    __syscall_slong_t __ru_ixrss_word;
  };
  /* Amount of data segment memory used (kilobyte-seconds).  */
  __extension__ union {
    long int ru_idrss;
    __syscall_slong_t __ru_idrss_word;
  };
  /* Amount of stack memory used (kilobyte-seconds).  */
  __extension__ union {
    long int ru_isrss;
    __syscall_slong_t __ru_isrss_word;
  };
  /* Number of soft page faults (i.e. those serviced by reclaiming
       a page from the list of pages awaiting reallocation.  */
  __extension__ union {
    long int ru_minflt;
    __syscall_slong_t __ru_minflt_word;
  };
  /* Number of hard page faults (i.e. those that required I/O).  */
  __extension__ union {
    long int ru_majflt;
    __syscall_slong_t __ru_majflt_word;
  };
  /* Number of times a process was swapped out of physical memory.  */
  __extension__ union {
    long int ru_nswap;
    __syscall_slong_t __ru_nswap_word;
  };
  /* Number of input operations via the file system.  Note: This
       and `ru_oublock' do not include operations with the cache.  */
  __extension__ union {
    long int ru_inblock;
    __syscall_slong_t __ru_inblock_word;
  };
  /* Number of output operations via the file system.  */
  __extension__ union {
    long int ru_oublock;
    __syscall_slong_t __ru_oublock_word;
  };
  /* Number of IPC messages sent.  */
  __extension__ union {
    long int ru_msgsnd;
    __syscall_slong_t __ru_msgsnd_word;
  };
  /* Number of IPC messages received.  */
  __extension__ union {
    long int ru_msgrcv;
    __syscall_slong_t __ru_msgrcv_word;
  };
  /* Number of signals delivered.  */
  __extension__ union {
    long int ru_nsignals;
    __syscall_slong_t __ru_nsignals_word;
  };
  /* Number of voluntary context switches, i.e. because the process
       gave up the process before it had to (usually to wait for some
       resource to be available).  */
  __extension__ union {
    long int ru_nvcsw;
    __syscall_slong_t __ru_nvcsw_word;
  };
  /* Number of involuntary context switches, i.e. a higher priority process
       became runnable or the current process used up its time slice.  */
  __extension__ union {
    long int ru_nivcsw;
    __syscall_slong_t __ru_nivcsw_word;
  };
};

/* Priority limits.  */
#define PRIO_MIN -20 /* Minimum priority a process can have.  */
#define PRIO_MAX 20  /* Maximum priority a process can have.  */

/* The type of the WHICH argument to `getpriority' and `setpriority',
   indicating what flavor of entity the WHO argument specifies.  */
enum __priority_which
{
  PRIO_PROCESS = 0, /* WHO is a process ID.  */
#define PRIO_PROCESS PRIO_PROCESS
  PRIO_PGRP = 1, /* WHO is a process group ID.  */
#define PRIO_PGRP PRIO_PGRP
  PRIO_USER = 2 /* WHO is a user ID.  */
#define PRIO_USER PRIO_USER
};