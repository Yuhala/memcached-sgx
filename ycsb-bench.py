#!/usr/bin/env python3

#
# Author: Peterson Yuhala
# September 22, 2021
# YCSB benchmarking script for zc switchless
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


YCSB_OUTPUT = YCSB_BASE + "/output.txt"
MAIN_RES = BASE_DIR + "/results/main.csv"
MCD_SGX_BIN = SGX_BASE + "/memcached-sgx"
YCSB_BIN = YCSB_BASE + "/bin/ycsb"
KILLER = SGX_BASE + "/kill.sh"

WORKLOAD = YCSB_BASE + " /workloads/workloada"

# minimum target throughput
MIN_TPUT = 500
# maximum target throughput
MAX_TPUT = 1000
# throughput step
STEP = 500

NUM_CLIENT_THREADS = 4
NUM_MCD_WORKER_THREADS = 4

# wait time (in seconds) for sgx process to start up; the delay here is based on experience
SLEEP = 90.0

# sample ycsb commands
# ./bin/ycsb run memcached - s - P workloads/workloada - p "memcached.hosts=127.0.0.1" - threads 4 > output.txt
# ./bin/ycsb run memcached - s - P workloads/workloada - p "memcached.hosts=127.0.0.1" - threads 4 -target 1000 > output.txt


# run memcached sgx
# this takes some time to start up so we will wait a little just to be sure
def run_mcd_sgx():
    print(f'................ Launching memcached-sgx ..................')
    # change directory to sgx bin base
    os.chdir(SGX_BASE)
    sgx_proc = subprocess.Popen([MCD_SGX_BIN, str(NUM_MCD_WORKER_THREADS)])
    print(
        f'................. Waiting for memcached-sgx process to startup. Wait time: {SLEEP}s ......................')
    time.sleep(SLEEP)
    print(f'............... memcached-sgx surely up by now :) .................')


def kill_mcd_sgx():
    print(f'.............. Killing memcached sgx process .....................')
    subprocess.call(KILLER)


# load ycsb data into mcd
def load_ycsb():
    # change directory to sgx bin base
    os.chdir(YCSB_BASE + "/bin")
    # command to load workload data into mcd
    ycsbLoad = " load memcached -s -P " + WORKLOAD + \
        " -p \"memcached.hosts=127.0.0.1\" -threads " + str(NUM_CLIENT_THREADS)

    ###
    print(f'............... Loading YCSB workload ...............')
    # start ycsb load process
    load_proc = subprocess.Popen([YCSB_BIN, str(ycsbLoad)])
    # wait for load to complete
    load_proc.wait()
    print(f'............... YCSB load complete ................')


# run ycsb workload
def run_ycsb(target_tput):
    # change directory to ycsb bin base
    os.chdir(YCSB_BASE + "/bin")
    # command to run ycsb workload
    ycsbRun = " run memcached -s -P " + WORKLOAD + \
        " -p \"memcached.hosts=127.0.0.1\" -threads " + \
        str(NUM_CLIENT_THREADS) + " -target " + \
        str(target_tput) + " > " + YCSB_OUTPUT

    ###
    print(f'............... Loading YCSB workload ...............')
    # start ycsb run process
    run_proc = subprocess.Popen([YCSB_BIN, str(ycsbRun)])
    # wait for run to complete
    run_proc.wait()
    print(f'............... YCSB run complete ................')


# parses ycsb output file and writes results to results file
def register_results(target_tput):
    print(f'............... Registering results ...................')

    with open(YCSB_OUTPUT) as file:
        # read lines from output file
        output_lines = file.readlines()

    # ycsb writes overall runtime on first line
    line0Vals = re.findall('[0-9]+', output_lines[0])
    total_runtime = int(line0Vals[0])  # in ms
    total_runtime_secs = total_runtime / 1000  # in s

    # ycsb writes overall tput on second line
    line1Vals = re.findall('[0-9]+', output_lines[1])
    avg_tput = float(line1Vals[0])

    # write final results
    with open(MAIN_RES, "a", newline='') as res_file:
        writer = csv.writer(res_file, delimiter=',')
        writer.writerow(target_tput, total_runtime_secs, avg_tput)

    print(f'............... Results registered ...................')


# run ycsb throughput latency bench
def run_bench_tput_lat():
    target = MIN_TPUT

    while(target <= MAX_TPUT):
        # launch the memcached-sgx server
        run_mcd_sgx()
        # load kv pairs into mcd-sgx
        load_ycsb()
        # run ycsb workload
        run_ycsb(target)
        # stop mcd server
        kill_mcd_sgx()
        # register run result
        register_results(target)
        # update target
        target += STEP


run_bench_tput_lat()
#print(f'script abs path is: {SCRIPT_ABS_PATH} and dir path is: {SCRIPT_DIR}')
