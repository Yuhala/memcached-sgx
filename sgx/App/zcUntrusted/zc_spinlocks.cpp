
/*
 * Created on Thu Sep 30 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * Copied from eleos sync utils
 *
 *
 *
 */

#include <sgx_spinlock.h>

/* void spin_lock(unsigned int volatile*p)
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
} */

void spin_lock(int volatile *p)
{
	while (!__sync_bool_compare_and_swap(p, 0, 1))
	{
		while (*p)
			__asm__("pause");
	}
}

void spin_unlock(int volatile *p)
{
	asm volatile(""); // acts as a memory barrier.
	*p = 0;
}

void spin_lock(unsigned char volatile *p)
{
	while (!__sync_bool_compare_and_swap(p, 0, 1))
	{
		while (*p)
			__asm__("pause");
	}
}

void spin_unlock(unsigned char volatile *p)
{
	asm volatile(""); // acts as a memory barrier.
	*p = 0;
}
