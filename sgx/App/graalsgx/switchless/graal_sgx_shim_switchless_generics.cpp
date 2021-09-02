#include "graal_sgx_shim_switchless_u.h"
#include "Enclave_u.h"

/* unsigned int sleep(unsigned int secs) */
/* int fsync(int fd) */
/* int close(int fd) */
void ocall_ret_int_args_int_switchless(struct buffer* switchless_buffer)
{
    int ret;
    int arg1;

    arg1 = *((int*) switchless_buffer->args);
    ret = ((int (*) (int)) switchless_buffer->ocall_handler)(arg1);
    *((int*) switchless_buffer->ret) = ret;
}

/* int dup2(int oldfd, int newfd) */
void ocall_ret_int_args_int_int_switchless(struct buffer* switchless_buffer)
{
    int ret;
    int arg1, arg2;

    arg1 = ((int*) switchless_buffer->args)[0];
    arg2 = ((int*) switchless_buffer->args)[1];
    ret = ((int (*) (int,int)) switchless_buffer->ocall_handler)(arg1, arg2);
    *((int*) switchless_buffer->ret) = ret;
}

/* int unlink(const char* pathname) */
/* int rmdir(const char* pathname) */
/* int remove(const char* pathname) */
void ocall_ret_int_args_const_string_switchless(struct buffer* switchless_buffer)
{
    int ret;
    const char* arg1;

    arg1 = (const char*) switchless_buffer->args;
    ret = ((int (*) (const char*)) switchless_buffer->ocall_handler)(arg1);
    *((int*) switchless_buffer->ret) = ret;
}
