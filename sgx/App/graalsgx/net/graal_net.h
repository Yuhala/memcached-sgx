#ifndef GRAAL_NET_H
#define GRAAL_NET_H


//extern char **environ;
// This prevents "name mangling" by g++ ---> PYuhala
#if defined(__cplusplus)
extern "C"
{
#endif

    void *transmit_prepare();

#if defined(__cplusplus)
}
#endif

#endif /* GRAAL_SGX_SHIM_SWITCHLESS_U_H */
