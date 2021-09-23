#!/usr/bin/env python3

#
# Author: Peterson Yuhala
# September 22, 2021
# YCSB benchmarking script for zc switchless
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

SGX_BASE = BASE_DIR + "/sgx"
YCSB_BASE = BASE_DIR + "/YCSB"

MCD_BASE = BASE_DIR + "/memcached"

YCSB_OUTPUT = YCSB_BASE + "/output.txt"
MAIN_RES = BASE_DIR + "/results/main.csv"
MCD_SGX_BIN = SGX_BASE + "/memcached-sgx"

MCD_BIN = MCD_BASE + "/memcached"

YCSB_BIN = YCSB_BASE + "/bin/ycsb"
KILLER = SGX_BASE + "/kill.sh"
YCSB_PROPS = YCSB_BASE + "/memcached/conf/memcached.properties"

WORKLOAD = YCSB_BASE + "/workloads/workloadc"
BASH_PATH = "/bin/bash"

# minimum target throughput
MIN_TPUT = 200
# maximum target throughput
MAX_TPUT = 5000
# throughput step
STEP = 200

NUM_CLIENT_THREADS = 2
NUM_MCD_WORKER_THREADS = 4

# wait time (in seconds) for sgx process to start up; the delay here is based on experience
SLEEP = 90.0

# line number in output files for specific workload avg latencies
# todo: find a better way to do this
READ_ONLY_AVG_LAT = 13

# sample ycsb commands
# ./bin/ycsb load memcached -s -P workloads/workloada -p "memcached.hosts=127.0.0.1" > output.txt
# ./bin/ycsb run memcached -s -P workloads/workloada -p "memcached.hosts=127.0.0.1" -threads 4 -target 1000 > output.txt


# run memcached sgx
# this takes some time to start up so we will wait a little just to be sure
def run_mcd_sgx():
    print(f'................ Launching memcached-sgx ..................')
    # change directory to sgx bin base
    os.chdir(SGX_BASE)
    # command to run memcached-sgx server; take note of the whitespace b4 the num of worker threads variable
    runCmd = MCD_SGX_BIN + f' {NUM_MCD_WORKER_THREADS}'
    sgx_proc = subprocess.Popen(runCmd, shell=True, executable=BASH_PATH)
    print(
        f'................. Waiting for memcached-sgx process to startup. Wait time: {SLEEP}s ......................')
    time.sleep(SLEEP)
    print(f'............... memcached-sgx surely up by now :) .................')

# run default memcached w/o sgx


def run_mcd():
    print(f'................ Launching memcached ..................')
    # change directory to sgx bin base
    os.chdir(MCD_BASE)
    # command to run memcached-sgx server; take note of the whitespace b4 the num of worker threads variable
    runCmd = MCD_BIN
    sgx_proc = subprocess.Popen(runCmd, shell=True, executable=BASH_PATH)
    print(
        f'................. Waiting for memcached process to startup. Wait time: 5s ......................')
    time.sleep(5)
    print(f'............... memcached-sgx surely up by now :) .................')


def kill_mcd():
    print(f'.............. Killing memcached process .....................')
    subprocess.call(KILLER)


# load ycsb data into mcd
# ./bin/ycsb.sh load memcached -s -P workloads/workloada -p "memcached.hosts=127.0.0.1" > outputLoad.txt
def load_ycsb():
    # change directory to sgx bin base
    os.chdir(YCSB_BASE)
    # carefully add all arguments in a list, including the binary path
    # loadArgs = [YCSB_BIN, "load", "memcached", "-s",
    #           "-P", WORKLOAD, "-p", "memcached.hosts=127.0.0.1"]

    # command to load ycsb data
    loadCmd = YCSB_BIN + \
        f' load memcached -s -P workloads/workloada -p memcached.hosts=127.0.0.1 -threads {NUM_CLIENT_THREADS}'
    # --------------------------------------------------
    print(f'............... Loading YCSB workload ...............')
    # start ycsb load process
    load_proc = subprocess.Popen(loadCmd, shell=True, executable=BASH_PATH)
    # wait for load to complete
    load_proc.wait()
    print(f'............... YCSB load complete ................')


# run ycsb workload
# ./bin/ycsb run memcached -s -P workloads/workloada -p "memcached.hosts=127.0.0.1" -threads 4 -target 1000 > output.txt
def run_ycsb(target_tput):
    # change directory to ycsb bin base
    os.chdir(YCSB_BASE)
    # ycsb run command
    runCmd = YCSB_BIN + \
        f' run memcached -s -P workloads/workloada -p memcached.hosts=127.0.0.1 -threads {NUM_CLIENT_THREADS} -target {target_tput} > {YCSB_OUTPUT}'
    # --------------------------------------------------
    print(f'............... Running YCSB workload ...............')
    # start ycsb run process
    run_proc = subprocess.Popen(runCmd, shell=True, executable=BASH_PATH)
    # wait for run to complete
    run_proc.wait()
    print(f'............... YCSB run complete ................')


# parses ycsb output file and writes results to results file
# todo: this routine would/may be wrong once the output structure changes; find a better way to parse
def register_results(target_tput, latency_line):
    print(f'............... Registering results ...................')

    with open(YCSB_OUTPUT) as file:
        # read lines from output file
        output_lines = file.readlines()

    latLine = re.findall('[0-9]+', output_lines[latency_line-1])
    avg_lat = float(latLine[0])  # in us
    avg_lat_ms = avg_lat / 1000  # in s

    # ycsb writes overall tput on second line
    tputLine = re.findall('[0-9]+', output_lines[1])
    avg_tput = float(tputLine[0])

    # write final results
    with open(MAIN_RES, "a", newline='') as res_file:
        writer = csv.writer(res_file, delimiter=',')
        writer.writerow([target_tput, avg_lat_ms, avg_tput])

    print(f'............... Results registered ...................')

# delete file


def clean(filename):
    if os.path.exists(filename):
        os.remove(filename)
    else:
        print(f'{filename} does not exist..')


# run ycsb throughput latency bench
def run_bench_tput_lat():
    target = MIN_TPUT

    while(target <= MAX_TPUT):
        # clean previous ycsb output file JIC
        clean(YCSB_OUTPUT)
        # launch the memcached-sgx server
        # run_mcd_sgx()
        run_mcd()
        # load kv pairs into mcd-sgx
        load_ycsb()
        # run ycsb workload
        run_ycsb(target)
        # stop mcd server
        kill_mcd()
        # register run result
        register_results(target, READ_ONLY_AVG_LAT)
        # update target
        target += STEP


run_bench_tput_lat()
#print(f'script abs path is: {SCRIPT_ABS_PATH} and dir path is: {SCRIPT_DIR}')

# Test routines
# run_mcd_sgx()
# load_ycsb()
# run_ycsb(5000)
# register_results(5000)
