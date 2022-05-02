#ifndef B0EEFAAE_B0B6_41A3_9ECD_364050919617
#define B0EEFAAE_B0B6_41A3_9ECD_364050919617

#include "stdlib.h"
#include  <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

int mem_initialize(void* ptr, size_t size, int mnReq);
int memsys5Init(void *NotUsed, void* ptr, size_t p_size, int mnReq);
void memsys5Free(void *pOld);
void *memsys5Malloc(int nByte);
int memsys5Roundup(int n);
int memsys5Size(void *p);

#ifdef __cplusplus
}
#endif


#endif /* B0EEFAAE_B0B6_41A3_9ECD_364050919617 */
