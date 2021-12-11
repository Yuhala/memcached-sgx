/*
 * Created on Wed Sep 29 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * Proof of concept ocalls using our zc switchless mechanism. Mostly io calls for the poc.
 * Future work: use the ocall-libc calls already defined in the shim untrusted side (internship)
 * 
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/times.h>
#include <sys/ioctl.h>
#include <dirent.h>

//zc headers
#include "ocall_logger.h"
#include "zc_types.h"
#include "zc_queues_out.h"
#include "zc_ocalls_out.h"

//headers from corresponding ocall shim helper lib
#include "io/io.h"
#include "net/graal_net.h"

#include "../App/bench/benchtools.h"

extern struct timespec start, stop;


void zc_read_switchless(zc_req *request)
{
    // call real ocall (no enclave transition since we are already outside)
    ((read_arg_zc *)request->args)->ret = ocall_read(((read_arg_zc *)request->args)->fd,
                                                     ((read_arg_zc *)request->args)->buf,
                                                     ((read_arg_zc *)request->args)->count);
}

void zc_write_switchless(zc_req *request)
{

    // call real ocall (no enclave transition since we are already outside)
    ((write_arg_zc *)request->args)->ret = ocall_write(((write_arg_zc *)request->args)->fd,
                                                       ((write_arg_zc *)request->args)->buf,
                                                       ((write_arg_zc *)request->args)->count);
}

void zc_transmit_prepare(zc_req *request)
{
    ((transmit_prepare_arg_zc *)request->args)->ret = transmit_prepare();
}

void zc_sendmsg_switchless(zc_req *request)
{
    // call real ocall (no enclave transition since we are already outside)
    struct msghdr *header = (struct msghdr *)((sendmsg_arg_zc *)request->args)->msg_header;
    ((sendmsg_arg_zc *)request->args)->ret = ocall_sendmsg(((sendmsg_arg_zc *)request->args)->sockfd,
                                                           header,
                                                           ((sendmsg_arg_zc *)request->args)->flags);
}

void zc_fwrite_switchless(zc_req *request)
{
    // call real ocall (no enclave transition since we are already outside)
    ((fwrite_arg_zc *)request->args)->ret = ocall_fwrite(((fwrite_arg_zc *)request->args)->buf,
                                                         ((fwrite_arg_zc *)request->args)->size,
                                                         ((fwrite_arg_zc *)request->args)->nmemb,
                                                         ((fwrite_arg_zc *)request->args)->stream);
}

void zc_fread_switchless(zc_req *request)
{
    // call real ocall (no enclave transition since we are already outside)
    ((fread_arg_zc *)request->args)->ret = ocall_fread(((fread_arg_zc *)request->args)->buf,
                                                       ((fread_arg_zc *)request->args)->size,
                                                       ((fread_arg_zc *)request->args)->nmemb,
                                                       ((fread_arg_zc *)request->args)->stream);
}

void zc_fseeko_switchless(zc_req *request)
{
    // call real ocall (no enclave transition since we are already outside)
    ((fseeko_arg_zc *)request->args)->ret = ocall_fseeko(((fseeko_arg_zc *)request->args)->stream,
                                                         ((fseeko_arg_zc *)request->args)->offset,
                                                         ((fseeko_arg_zc *)request->args)->whence);
}

void zc_test_switchless(zc_req *request)
{
    ((test_arg_zc *)request->args)->ret = ocall_test(((test_arg_zc *)request->args)->a,
                                                     ((test_arg_zc *)request->args)->b);
}

int zc_fsync_switchless(zc_req *request)
{

    start_clock();
    ((fsync_arg_zc *)request->args)->ret = ocall_fsync(((fsync_arg_zc *)request->args)->fd);
    stop_clock();
    double totalRuntime = time_diff(&start, &stop, SEC);
    printf("FSYNC TIME: %f >>>>>>>>>>>>>>>>>>>>\n", totalRuntime);
}
void zc_sync_switchless(zc_req *request)
{
    ocall_sync();
}
int zc_ftruncate64_switchless(zc_req *request)

{
    start_clock();
    ((ftruncate64_arg_zc *)request->args)->ret = ocall_ftruncate64(((ftruncate64_arg_zc *)request->args)->fd,
                                                                   ((ftruncate64_arg_zc *)request->args)->length);

    stop_clock();
    double totalRuntime = time_diff(&start, &stop, SEC);
    printf("FTRUNCATE TIME: %f >>>>>>>>>>>>>>>>>>>>\n", totalRuntime);
}

void zc_f(zc_req *request)
{
    ocall_f();
}

void zc_g(zc_req *request)
{
    ocall_g();
}
