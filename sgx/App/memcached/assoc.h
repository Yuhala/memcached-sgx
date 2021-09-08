
#if defined(__cplusplus)
extern "C"
{
#endif


void stop_assoc_maintenance_thread(void);
int sgx_start_assoc_maintenance_thread();
void *e_assoc_maintenance_thread(void *input);



extern unsigned int hashpower;
extern unsigned int item_lock_hashpower;



#if defined(__cplusplus)
}
#endif

