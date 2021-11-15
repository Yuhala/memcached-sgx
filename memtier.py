#!/usr/bin/env python3

#
# Author: Peterson Yuhala
# November 15, 2021
# Memtier benchmarking script for zc switchless
#

#
# pyuhala: Opening bash subprocesses with arguments can be tricky sometimes
# have a look at this thread for inspiration and guidance in case you have weird issues
# https://stackoverflow.com/a/50553425
#

import os
import subprocess
import time
import csv
import math
import statistics
import re  # for regular expressions
from random import randint

# Get the base directory using absolute path of this script
# NB: this script should be in the memcached-sgx directory
SCRIPT_ABS_PATH = os.path.abspath(__file__)
BASE_DIR = os.path.dirname(SCRIPT_ABS_PATH)


# Get the base directory using absolute path of this script
# NB: this script should be in the memcached-sgx directory
SCRIPT_ABS_PATH = os.path.abspath(__file__)
BASE_DIR = os.path.dirname(SCRIPT_ABS_PATH)

SGX_BASE = BASE_DIR + "/sgx"
MEMTIER_BASE = BASE_DIR + "/memtier_benchmark"

MCD_BASE = BASE_DIR + "/memcached"

MAIN_RES = BASE_DIR + "/results/main.csv"
MCD_SGX_BIN = SGX_BASE + "/memcached-sgx"

MCD_BIN = MCD_BASE + "/memcached"


KILLER = SGX_BASE + "/kill.sh"
BASH_PATH = "/bin/bash"

#MCD_HOST_IP = "127.0.0.1"
#MCD_HOST_IP = "172.28.30.136"  # eiger-10.maas ip
MCD_HOST_IP = "172.28.30.235"  # pilatus-1.maas ip

MIN_CONNS = 1
MAX_CONNS = 20

MIN_DATA = 1
MAX_DATA = 32

MIN_THREADS = 1
MAX_THREADS = 16

# wait time (in seconds) for sgx process to start up; the delay here is based on experience
SLEEP = 25.0

# line prefixes for given output, based on ycsb output files
# pyuhala: NB: DO NOT CHANGE ANYTHING IN THESE STRINGS; spaces, commas, NOTHING!!!


GETS = "Gets"
SETS = "Sets"
TOTALS = "Totals"

# sample memtier commands
# ./memtier_benchmark -s 172.28.30.235 -p 11211 -c 10 -x 5 -t 4 -n 500 -P memcache_binary --ratio=1:1


# run memcached sgx
# this takes some time to start up so we will wait a little just to be sure
# arg1 = zc, arg2 = intel
def run_mcd_sgx(is_zc,is_intel):
    print(f'................ Launching memcached-sgx ..................')
    # change directory to sgx bin base
    os.chdir(SGX_BASE)
    # command to run memcached-sgx server; take note of the whitespace b4 "is_zc"
    runCmd = MCD_SGX_BIN + f' {is_zc} {is_intel}'
    sgx_proc = subprocess.Popen(runCmd, shell=True, executable=BASH_PATH)
    print(
        f'................. Waiting for memcached-sgx process to startup. Wait time: {SLEEP}s ......................')
    time.sleep(SLEEP)
    print(f'............... memcached-sgx surely up by now :) .................')

# run default memcached w/o sgx


