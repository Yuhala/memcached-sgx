/*
 * Created on Tue Mar 23 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * Defines routines used to count ocall transitions
 */

#include "ocall_logger.h"
#include "stdlib.h"
#include "stdio.h"
#include <bits/stdc++.h>
#include <numeric>
#include <map>

using namespace std;
unsigned int ocall_count = 0;
std::map<std::string, int> ocall_map;

pthread_mutex_t ocall_counter_lock;

// Comparator function to sort pairs in ascending order
bool cmp(pair<string, int> &a,
         pair<string, int> &b)
{
    return a.second > b.second;
}

void log_ocall(const char *func)
{
    /**
     * lock is important when we have multiple 
     * workers calling this routine
     */
    pthread_mutex_lock(&ocall_counter_lock);
    ocall_count++;

    std::string name = std::string(func);

    if (ocall_map.find(name) != ocall_map.end())
    {
        //kv pair exists in map
        ocall_map[name] += 1;
    }
    else
    {
        //kv pair does not exist yet
        ocall_map.insert(std::make_pair(name, 1));
    }
    pthread_mutex_unlock(&ocall_counter_lock);
    //printf("Calling ocall is: %s\n", name);
}

/**
 * Print top num frequent ocalls
 */
void show_ocall_log(int num)
{
    //create vector with map kv pairs
    vector<pair<string, int>> vect;

    for (auto &it : ocall_map)
    {
        vect.push_back(it);
    }
    //printf("size of vect is: %d\n",vect.size());
    //sort vector
    sort(vect.begin(), vect.end(), cmp);
    int count = 0;
    //print first num elements in the vector
    printf("----------------------- OCALL STATS: Top %d ---------------------------\n", num);
    for (auto &it : vect)
    {
        printf("Ocall: %s Count: %d\n", it.first.c_str(), it.second);
        count++;
        if (count >= num)
        {
            break;
        }
    }

    //calculate totals: use accumulate next time.. pyuhala
    int total = 0;
    for (auto &it : vect)
    {
        total += it.second;
    }
    printf("Total ocalls: %d \n", total);
}