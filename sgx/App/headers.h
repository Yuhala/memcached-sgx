#ifndef D7A67088_9088_4607_92B6_5935AC28B5F8
#define D7A67088_9088_4607_92B6_5935AC28B5F8

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "graalsgx/net/graal_net.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/sysinfo.h>
#include <cassert>
#define assertm(exp, msg) assert(((void)msg, exp))
//#define ____sigset_t_defined
#define __iovec_defined 1

#include "Enclave_u.h"
#include "sgx_urts.h"

#include <sgx_spinlock.h>

#include "error/error.h"

// Graal headers
#include "graal_isolate.h"
#include "main.h"
#include "user_types.h"

// switchless headers
#include "switchless_buffer.h"
#include <sched.h>
#include <sys/syscall.h>

/* Signal handlers */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <map>
#include "ocall_logger.h"

#include "graal_sgx_shim_switchless_u.h"

//zc switchless
#include "zcUntrusted/zc_out.h"

//intel sdk switchless lib
#include <sgx_uswitchless.h>

//for get_nprocs()
#include <sys/sysinfo.h>

#include "zc_types.h"

/* Benchmarking */
#include "bench/benchtools.h"
#include "bench/cpu_usage.h"
#include <time.h>

/* Macro for this value which is in the config file of the enclave because I
 * don't know how to do better
 */
// pyuhala: these should not be fixed b/c they are machine dependent; try using
// global variables instead, which you can set to the right values at the start of the program
// for example: num of cores can be obtained with get_nprocs()

#define SGX_TCS_NUM 8
#define CORES_NUM 4
#define TIME_ENCLAVE_SWITCH 13500
#define TIME_MICRO_QUANTUM 100000 // 1000000 = 1ms
#define MICRO_INVERSE 100
#define CPU_FREQ 3.8

#endif /* D7A67088_9088_4607_92B6_5935AC28B5F8 */
