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

WORKLOAD = YCSB_BASE + "/workloads/workloada"
BASH_PATH = "/bin/bash"

# minimum target throughput
MIN_TPUT = 2000
# maximum target throughput
MAX_TPUT = 50000
# throughput step
STEP = 2000

NUM_CLIENT_THREADS = 4
NUM_MCD_WORKER_THREADS = 4

# wait time (in seconds) for sgx process to start up; the delay here is based on experience
SLEEP = 90.0

# line prefixes for given output, based on ycsb output files
READ_ONLY_AVG_LAT = "[READ], AverageLatency(us)"
UPDATE_ONLY_AVG_LAT = "[UPDATE], AverageLatency(us)"
OVERALL_TPUT = "[OVERALL], Throughput(ops/sec)"
OVERALL_RUNTIME = "[OVERALL], RunTime(ms)"


# sample ycsb commands
# ./bin/ycsb load memcached -s -P workloads/workloadc -p memcached.hosts=127.0.0.1 > output.txt
# ./bin/ycsb run memcached -s -P workloads/workloadc -p memcached.hosts=127.0.0.1 -threads 4 -target 1000 > output.txt


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


# returns line containing specific text
def get_output_line(text, output_lines):
    for line in output_lines:
        if text in line:
            return line

    return "0"
# parses ycsb output file and writes results to results file
# todo: this routine would/may be wrong once the output structure changes; find a better way to parse


def register_results(target_tput, latency_line):
    print(f'............... Registering results ...................')

    with open(YCSB_OUTPUT) as file:
        # read lines from output file
        output_lines = file.readlines()

    # get read only avg latency
    read_lat_line = get_output_line(READ_ONLY_AVG_LAT, output_lines)
    read_vals = re.findall('[0-9]+', read_lat_line)
    read_avg = float(read_vals[0])/1000  # in ms

    # get update only avg latency
    upd_lat_line = get_output_line(UPDATE_ONLY_AVG_LAT, output_lines)
    upd_vals = re.findall('[0-9]+', upd_lat_line)
    upd_avg = float(upd_vals[0])/1000  # in ms

    # get overall tput
    tput_line = get_output_line(OVERALL_TPUT, output_lines)
    tput_vals = re.findall('[0-9]+', tput_line)
    tput_avg = float(tput_vals[0])

    # write final results
    with open(MAIN_RES, "a", newline='') as res_file:
        writer = csv.writer(res_file, delimiter=',')
        writer.writerow([target_tput, read_avg, upd_avg, tput_avg])

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
