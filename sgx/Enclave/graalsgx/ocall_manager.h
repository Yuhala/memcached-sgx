#ifndef OCALL_MANAGER_H
#define OCALL_MANAGER_H

#include "graal_sgx_shim_switchless.h"
#include "Enclave_t.h"

#if defined(__cplusplus)
extern "C"
{
#endif

    void log_ocall(enum fn_token t);
    int should_be_switchless(enum fn_token t);

#if defined(__cplusplus)
}
#endif

#endif /* OCALL_MANAGER_H */
