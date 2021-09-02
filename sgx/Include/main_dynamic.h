#ifndef __MAIN_H
#define __MAIN_H

#include <graal_isolate_dynamic.h>


#if defined(__cplusplus)
extern "C" {
#endif

typedef void (*readN_fn_t)(graal_isolatethread_t*, int, int);

typedef void (*writeN_fn_t)(graal_isolatethread_t*, int, int);

typedef int (*run_main_fn_t)(int argc, char** argv);

typedef void (*vmLocatorSymbol_fn_t)(graal_isolatethread_t* thread);

#if defined(__cplusplus)
}
#endif
#endif
