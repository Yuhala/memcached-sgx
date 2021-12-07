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
    size_t ocall_fwrite(const void *ptr, size_t size, size_t nmemb, SGX_FILE stream);
    size_t ocall_fread(void *ptr, size_t size, size_t nmemb, SGX_FILE stream);
    ssize_t ocall_read(int fd, void *buf, size_t count);
    ssize_t ocall_write(int fd, const void *buf, size_t count);

    void ocall_sync(void);
    int ocall_fsync(int fd);
    int ocall_ftruncate64(int fd, off_t length);

    int ocall_fseeko(SGX_FILE stream, off_t offset, int whence);
    off_t ocall_ftello(SGX_FILE stream);

    int ocall_test(int a, int b);
    void ocall_f();
    void ocall_g();

#if defined(__cplusplus)
}
#endif

#endif
