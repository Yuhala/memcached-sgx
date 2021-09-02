/*
 * Created on Wed Jul 15 2020
 *
 * Copyright (c) 2020 Peterson Yuhala, IIUN
 */

#ifndef GRAAL_SGX_SHIM_SWITCHLESS_U_H
#define GRAAL_SGX_SHIM_SWITCHLESS_U_H





//extern char **environ;
// This prevents "name mangling" by g++ ---> PYuhala
#if defined(__cplusplus)
extern "C"
{
#endif

    void ocall_empty_switchless(struct buffer* switchless_buffer);
    //io
    //int open(const char *path, int oflag, ...);
    void ocall_ret_int_args_int_switchless(struct buffer* switchless_buffer);
    void ocall_ret_int_args_int_int_switchless(struct buffer* switchless_buffer);
    void ocall_ret_int_args_const_string_switchless(struct buffer* switchless_buffer);
    void ocall_fwrite_switchless(struct buffer* switchless_buffer);
    void ocall_read_switchless(struct buffer* switchless_buffer);
    void ocall_write_switchless(struct buffer* switchless_buffer);
    void ocall_lseek64_switchless(struct buffer* switchless_buffer);


#if defined(__cplusplus)
}
#endif

#endif /* GRAAL_SGX_SHIM_SWITCHLESS_U_H */
