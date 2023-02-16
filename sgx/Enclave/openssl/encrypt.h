#ifndef ENCRYPT_H
#define ENCRYPT_H

#include "stdlib.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include <string.h>
#include <stdlib.h>

#define BUFLEN 4 * 1024 * 1024 // 1MB: increase this if you have to encrypt larger buffers
#define SGX_AESGCM_MAC_SIZE 16 // 128 bit mac
#define SGX_AESGCM_IV_SIZE 12  // 96 bit iv
#define CIPHERTEXT_SIZE 36
#define ADD_ENC_DATA_SIZE (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE)

#define ENABLE_CRYPTO

typedef enum
{
    ENCRYPT, //
    DECRYPT,
    DEFAULT
} ENC_FLAG;

typedef enum
{
    GCM, //
    CTR
} AES_ALGO;

#ifdef __cplusplus
extern "C"
{
#endif

    /* Cryptography API */
    void encryptData(void *dataIn, size_t len, char *dataOut, size_t lenOut, AES_ALGO algo);
    void decryptData(char *dataIn, size_t len, void *dataOut, size_t lenOut, AES_ALGO algo);
    /* encrypted memcpy i.e encrypt src and write ciphertext to dest */
    // void enc_memcpy(void *dest, void *src, size_t n, ENC_FLAG flag);

    int encrypt(unsigned char *plaintext,
                int plaintext_len,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *ciphertext);

    int decrypt(unsigned char *ciphertext,
                int ciphertext_len,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *plaintext);

    void handleErrors(void);
    void test_crypto ();

#ifdef __cplusplus
}
#endif

#endif /* ENCRYPT_H */