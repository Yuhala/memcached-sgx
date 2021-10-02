/*
 * Created on Sat Oct 02 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * 
 * ZC switchless cache implementation; follows a least frequently used algorithm to replace routines in the switchless cache.
 * Based on lfu cache implem: https://www.geeksforgeeks.org/least-frequently-used-lfu-cache-implementation/
 * 
 */

// C++ program for LFU cache implementation

#include "zc_lfu.h"
#include "Enclave.h"
/**
 * This vector is ordered in the form of a min heap and contains a function id
 * as well as the number of times the corresponding function has been called.
 */
std::vector<std::pair<int, int>> zc_switchless_cache(ZC_LFU_CACHE_SIZE);
/**
 * This is a hashmap which contains indices of all functions of the shim library which have been called
 * since the start of the enclave, as well as the number of times each function was called.
 */
std::unordered_map<int, int> zc_map;

int curr_cache_size = 0; /* number of items in the cache */

int number_of_ocalls = 0; /* total number of ocalls/shim function calls since enclave start */

// Generic function to swap two pairs
void swap(std::pair<int, int> &a, std::pair<int, int> &b)
{
    std::pair<int, int> temp = a;
    a = b;
    b = temp;
}

// Returns the index of the parent node
inline int parent(int i)
{
    return (i - 1) / 2;
}

// Returns the index of the left child node
inline int left(int i)
{
    return 2 * i + 1;
}

// Returns the index of the right child node
inline int right(int i)
{
    return 2 * i + 2;
}

// Self made heap tp Rearranges
//  the nodes in order to maintain the heap property
void heapify(std::vector<std::pair<int, int>> &v,
             std::unordered_map<int, int> &m, int i, int n)
{
    int l = left(i), r = right(i), minim;
    if (l < n)
        minim = ((v[i].second < v[l].second) ? i : l);
    else
        minim = i;
    if (r < n)
        minim = ((v[minim].second < v[r].second) ? minim : r);
    if (minim != i)
    {
        m[v[minim].first] = i;
        m[v[i].first] = minim;
        swap(v[minim], v[i]);
        heapify(v, m, minim, n);
    }
}
void increment(std::vector<std::pair<int, int>> &v,
               std::unordered_map<int, int> &m, int i, int n)
{
    ++v[i].second;
    heapify(v, m, i, n);
}

// Function to Insert a new node in the heap
void insert(std::vector<std::pair<int, int>> &v,
            std::unordered_map<int, int> &m, int value, int &n)
{

    if (n == v.size())
    {
        m.erase(v[0].first);
#ifdef ZC_CACHE_TEST
        printf("---------------------zc function: %d removed ------------------\n", v[0].first);
#endif
        v[0] = v[--n];
        heapify(v, m, 0, n);
    }
    v[n++] = std::make_pair(value, 1);
    m.insert(std::make_pair(value, n - 1));
    int i = n - 1;

    // Insert a node in the heap by swapping elements
    while (i && v[parent(i)].second > v[i].second)
    {
        m[v[i].first] = parent(i);
        m[v[parent(i)].first] = i;
        swap(v[i], v[parent(i)]);
        i = parent(i);
    }
#ifdef ZC_CACHE_TEST
    printf("---------------------zc function: %d inserted ------------------\n", value);
#endif
}

// Function to refer to the block/function value in the cache
void refer(std::vector<std::pair<int, int>> &cache, std::unordered_map<int, int> &indices, int value, int &cache_size)
{
    if (indices.find(value) == indices.end())
        insert(cache, indices, value, cache_size);
    else
        increment(cache, indices, indices[value], cache_size);
}

/**
 * Initialize all routine call counts in hashmap as 0
 */
void init_zc_map()
{
    /*for (int i = ZC_FREAD; i < ZC_LAST; i++)
    {
        zc_map[i] = 0;
    }*/
}

/**
 * This function tests if a function should be called as zc switchless or not; 
 * it replaced routines in the switchless cache following a least frequently used algorithm.
 */
bool use_zc_switchless(zc_routine func_name)
{
    number_of_ocalls++;

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
    refer(zc_switchless_cache, zc_map, (int)func_name, curr_cache_size);

    /**
     * check for switchless hit/miss (ie is fxn in cache or not)
     */

    bool test = false;
    for (int i = 0; i < zc_switchless_cache.size(); i++)
    {
        if (zc_switchless_cache[i].first == (int)func_name)
        {
            test = true;
            break;
        }
    }

    return test;
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