

#ifndef ZC_LFU_H
#define ZC_LFU_H

#include "zc_types.h"

#include <string>
#include <vector>
#include <iterator>
#include <typeinfo>
#include <functional>
#include <algorithm>
#include <unordered_set>
#include <unordered_map>
#include <initializer_list>
#include <tuple>
#include <memory>
#include <atomic>
#include <map>
#include <utility>

#define ZC_LFU_CACHE_SIZE 2 /* max number of routines which will be zc switchless */
#define ZC_LFU_INIT_NUM 0  /* number of ocalls done since the start of enclave b4 zc switchless is activated */

//#define ZC_CACHE_TEST

void swap(std::pair<int, int> &a, std::pair<int, int> &b);
void heapify(std::vector<std::pair<int, int>> &v,
             std::unordered_map<int, int> &m, int i, int n);
void increment(std::vector<std::pair<int, int>> &v,
               std::unordered_map<int, int> &m, int i, int n);

void insert(std::vector<std::pair<int, int>> &v,
            std::unordered_map<int, int> &m, int value, int &n);

void refer(std::vector<std::pair<int, int>> &cache, std::unordered_map<int, int> &indices, int value, int &cache_size);
void init_zc_map();
bool use_zc_switchless();

//test
void use_zc_test();

#endif /* ZC_LFU_H */
