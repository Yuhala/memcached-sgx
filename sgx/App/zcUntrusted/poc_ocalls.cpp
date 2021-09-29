/*
 * Created on Wed Sep 29 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * Proof of concept ocalls using our zc switchless mechanism. Mostly io calls for the poc.
 * Future work: use the ocall-libc calls already defined in the shim untrusted side.
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
#include "ocall_logger.h"
#include "zc_out.h"

//headers from corresponding ocall shim helper lib
#include "io/io.h"

