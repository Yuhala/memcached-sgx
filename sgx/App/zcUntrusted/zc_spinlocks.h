

#ifndef ZC_SPINLOCKS_H
#define ZC_SPINLOCKS_H

void spin_lock(int volatile *p);
void spin_unlock(int volatile *p);
void spin_lock(unsigned char volatile *p);
void spin_unlock(unsigned char volatile *p);

#endif /* ZC_SPINLOCKS_H */
