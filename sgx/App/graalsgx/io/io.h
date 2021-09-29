#ifndef __IO_H__
#define __IO_H__

#include <dirent.h>
#include "struct/sgx_stdio_struct.h"
#include <stdio.h>

//forward declarations
FILE *getFile(SGX_FILE stream);

#if defined(__cplusplus)
extern "C"
{
#endif

    void ocall_print_string(const char *str);

#if defined(__cplusplus)
}
#endif

#endif
