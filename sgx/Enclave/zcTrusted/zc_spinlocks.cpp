
/*
 * Created on Thu Sep 30 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * 
 * 
 * 
 * 
 */

#include <sgx_spinlock.h>

void spin_lock(unsigned int volatile*p)
{
	sgx_spin_lock(p);
}

void spin_unlock(unsigned int volatile*p)
{
	sgx_spin_unlock(p);
}

void spin_lock(unsigned char volatile *p)
{
	sgx_spin_lock((unsigned int volatile*)p);
}

void spin_unlock(unsigned char volatile *p)
{
	sgx_spin_unlock((unsigned int volatile*)p);
}