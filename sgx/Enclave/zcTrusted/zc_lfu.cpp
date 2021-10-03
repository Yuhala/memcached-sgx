/*
 * Created on Sat Oct 02 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * 
 * ZC switchless cache implementation; follows a least frequently used algorithm to replace routines in the switchless cache.
 * Revision on LFU : https://www.geeksforgeeks.org/least-frequently-used-lfu-cache-implementation/
 * 
 */

#include "zc_lfu.h"
#include "Enclave.h"

//forward declarations
static int is_in_cache(std::vector<std::pair<int, int>> &v, zc_routine func_name);

/**
 * This vector is ordered in the form of a min heap and contains a function id
 * as well as the number of times the corresponding function has been called.
 */
std::vector<std::pair<int, int>> zc_switchless_cache;

/**
 * This is a hashmap which contains indices of all functions of the shim library which have been called
 * since the start of the enclave, as well as the number of times each function was called.
 */
std::unordered_map<int, int> zc_map;
std::unordered_map<int, int> cache_map; /* map for routines already in cache */

int curr_cache_size = 0; /* number of items in the cache */

int number_of_ocalls = 0; /* total number of ocalls/shim function calls since enclave start */

/**
 * This function tests if a function should be called as zc switchless or not; 
 * it replaced routines in the switchless cache following a least frequently used algorithm.
 */
bool use_zc_switchless(zc_routine func_name)
{
#ifdef POC
    return true;
#endif

    number_of_ocalls++;
    int f = (int)func_name;
    bool test = false; /* true if func is inserted in cache ==> switchless hit; otherwise switchless miss */

    /**
     * pyuhala: maybe we should let the system "initialize for abit"
     * before actually using switchless calls. This way we don't begin having switchless calls
     * at the very first ocall. Just an idea for now..
     */
    if (number_of_ocalls < ZC_LFU_INIT_NUM)
    {
        //return false;
    }

    /**
     * Update switchless cache && function map
     */
    if (zc_map.find(f) == zc_map.end())
    {
        zc_map[f] = 1;
    }
    else
    {
        zc_map[f]++;
    }

    test = cache_insert(zc_switchless_cache, func_name);

    return test;
}

static int is_in_cache(std::vector<std::pair<int, int>> &v, zc_routine func_name)
{
    int f = (int)func_name;

    for (int i = 0; i < v.size(); i++)
    {
        if (v[i].first == f)
        {
            return i;
        }
    }
    return NOT_IN_CACHE;
}

/**
 * Try to insert a value in the cache
 */

bool cache_insert(std::vector<std::pair<int, int>> &v, zc_routine func_name)
{
    /**
     * check if function is already in cache
     */
    int index = is_in_cache(v, func_name);
    if (index != NOT_IN_CACHE)
    {
        //printf(" ----------------------- function %d already in cache ------------------\n", (int)func_name);
        v[index].second++;
        return true;
    }

    int f = (int)func_name;
    /* it should be in the map already */
    int count = zc_map[f];
    bool inserted = false;

    /* inserting a cache entry */
    if (v.size() < ZC_LFU_CACHE_CAPACITY)
    {
        //printf("--curr cache size: %d----\n", curr_cache_size);

        std::pair<int, int> entry = std::make_pair(f, count);
        //v.insert causing some issues, no time to waste ..
        v.push_back(entry);
        curr_cache_size++;
        //v[curr_cache_size++] = entry;

#ifdef ZC_CACHE_TEST
        printf("---------------------zc function: %d inserted ------------------\n", f);
#endif
        return true;
    }

    /* replacing a cache entry */

    int minIndex = findLeastFrequent(v);
    if (v[minIndex].second <= count)
    {
#ifdef ZC_CACHE_TEST
        printf("---------------------zc function: %d removed ------------------\n", v[minIndex].first);
        printf("---------------------zc function: %d inserted ------------------\n", f);

#endif
        std::pair<int, int> entry = std::make_pair(f, count);
        // replace cache entry at min index
        v[minIndex] = entry;
        inserted = true;
    }

    return inserted;
}

int findLeastFrequent(std::vector<std::pair<int, int>> &v)
{
    /**
     * This function is Ok when cache size is small.
     * For larger cache size use a min-heap which is more efficient
     * to track the smallest element
     */
    int minIndex = 0;
    for (int i = 0; i < v.size(); i++)
    {
        if (v[i].second < v[minIndex].second)
        {
            minIndex = i;
        }
    }
    return minIndex;
}

/**
 * Initialize all routine call counts in hashmap as 0
 */
void clear_zc_cache()
{
    //TODO
}

void use_zc_test()
{
    /**
     * Simulating routine calls and zc switchless routine choice. 
     */
    zc_routine call_array[9] = {ZC_FREAD, ZC_WRITE, ZC_FREAD, ZC_FWRITE, ZC_FWRITE, ZC_FWRITE, ZC_WRITE, ZC_WRITE, ZC_READ};

    for (int i = 0; i < 9; i++)
    {
        if (use_zc_switchless(call_array[i]))
        {
            printf("<<<<<<< using zc for function: %d >>>>>>>\n", (int)call_array[i]);
        }
        else
        {
            printf("<<<<<<< NOT using zc for function: %d >>>>>>>\n", (int)call_array[i]);
        }
    }
}