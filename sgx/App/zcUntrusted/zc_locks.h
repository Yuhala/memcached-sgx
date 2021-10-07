#ifndef ZC_LOCKS_H
#define ZC_LOCKS_H

#include <stdint.h>



uint32_t zc_spin_lock(volatile int *lock);
uint32_t zc_spin_unlock(volatile int *lock);

#endif /* ZC_LOCKS_H */
