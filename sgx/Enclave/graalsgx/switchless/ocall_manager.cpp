#include "ocall_manager.h"
#include "Enclave.h"

unsigned int number_of_calls[FN_TOKEN_TOTAL_SIZE] = {0};
unsigned int total_number_of_calls = 0;

extern volatile sig_atomic_t *number_of_sl_calls;
extern volatile sig_atomic_t *number_of_fallbacked_calls;
extern struct buffer *switchless_buffers;
extern __thread struct buffer *switchless_buffer;
extern volatile int *number_of_workers;

/* Every time a shim library function is called, it should call this function to
 * influence the future results of `should_be_switchless`
 */
void log_ocall(enum fn_token t)
{
	number_of_calls[t]++;
	total_number_of_calls++;
}

/* n >= 2 */
int is_in_top_n_calls(unsigned int n, enum fn_token t)
{
	// algorithmically inefficient
	unsigned int i, j;
	unsigned int tmp;
	unsigned int arr[FN_TOKEN_TOTAL_SIZE]; // we only use the first n elements

	if (n == 0)
		return 0;

	for (i = 0; i < n; i++)
		arr[i] = 0;
	for (i = 0; i < FN_TOKEN_TOTAL_SIZE; i++)
	{
		if (arr[n - 1] < number_of_calls[i])
		{
			arr[n - 1] = number_of_calls[i];
			for (j = n; j > 1; j--)
			{
				if (arr[j - 2] < arr[j - 1])
				{
					tmp = arr[j - 1];
					arr[j - 1] = arr[j - 2];
					arr[j - 2] = tmp;
				}
				else
					break;
			}
		}
	}

	return number_of_calls[t] >= arr[n - 1];
}

/* Returns whether a given shim library function call should be switchless or
 * not
 */

int should_be_switchless(enum fn_token t)
{
	return 0;
	//    return is_in_top_n_calls(2, t);
	static int oldi = 0;
	int i, j;
	int found = 0;
	int now = *number_of_workers;

	for (i = 0; i < now && !found; i++)
	{
		// j = (i + oldi) % now;
		j = i % now;
		if (switchless_buffers[j].status == BUFFER_UNUSED)
		{
			sgx_spin_lock(&switchless_buffers[j].spinlock);
			if (switchless_buffers[j].status == BUFFER_UNUSED)
			{
				switchless_buffers[j].status = BUFFER_RESERVED;
				switchless_buffer = &switchless_buffers[j];
				found = 1;
			}
			sgx_spin_unlock(&switchless_buffers[j].spinlock);
		}
	}

	if (found)
		__atomic_fetch_add(number_of_sl_calls, 1, __ATOMIC_SEQ_CST);
	else
		__atomic_fetch_add(number_of_fallbacked_calls, 1, __ATOMIC_SEQ_CST);
	return found;
}
