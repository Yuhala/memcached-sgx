#
# Author: Peterson Yuhala
# Script to do simple data analysis on csv files
# For example: compare the average ratios of columns
#

import os
import subprocess
import time
import csv
import math
import statistics 
import pandas
from random import randint

FILE1 = "./paldb/ocalls-part-W.csv"
FILE2 = "./paldb/ocalls-part-R.csv"

NAN0 = 0.000000001
MICRO = 0.000001
MILLIS = 0.001

#
# Columns to be compared: should be the same as in csv files
# Ratios are col1/col2
#
def get_avg_ratios(col1_name,col2_name):
    col1 = pandas.read_csv(FILE1)[col1_name].tolist()
    col2 = pandas.read_csv(FILE2)[col2_name].tolist()

    #col1 = col1.tolist()
    #col2 = col2.tolist()

    #print(f'Col1: {col1}')
    #print(f'Col2: {col2}')

    #get min list size
    size = min(len(col1),len(col2))
    print(f'Col 1: {col1}')
    print(f'Col 2: {col2}')
    print(f'Min size is: {size}')

    #calculate average ratios
    ratios = []

    for i in range(size):
        cur = col1[i]/(col2[i])
        ratios.append(cur)
    
    print(f'Ratios: {ratios}')
    meanRatio = statistics.mean(ratios)
    print(f'>>>>>>>>>>>> Average ratio: {meanRatio}')

# some column names in benchmarking files: 
#"out->in(s)","in->out(s)","no-proxy-out(ns)","no-proxy-in(ns)"
#"no proxy in (ns)", "no proxy out(ns)" "in->out","out->in(ns)", "in->out+serial(ns)","out->in+serial(ns)"

# replace the parameters with the names of the columns to be compared 
get_avg_ratios("# of ocalls","# of ocalls")