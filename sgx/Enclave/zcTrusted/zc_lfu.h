

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

#define ZC_LFU_CACHE_CAPACITY 2 /* max number of routines which will be zc switchless */
#define ZC_LFU_INIT_NUM 0  /* number of ocalls done since the start of enclave b4 zc switchless is activated */

#define NOT_IN_CACHE -1
#define POC 1 /* if we are doing proof of concept, perform switchless call on the tested routines w/o lfu cache */
//#define ZC_CACHE_TEST


bool use_zc_switchless_lfu(zc_routine func_name);
bool cache_insert(std::vector<std::pair<int, int>> &v, zc_routine func_name);
int findLeastFrequent(std::vector<std::pair<int, int>> &v);
void clear_zc_cache();
//test
void use_zc_test();

#endif /* ZC_LFU_H */
