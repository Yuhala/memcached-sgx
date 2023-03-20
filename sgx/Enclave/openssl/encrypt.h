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
#define CHUNK_SIZE 32 // bytes

#define ENABLE_CRYPTO

typedef enum
{
    ENCRYPT, //
    DECRYPT,
    DEFAULT
} ENC_FLAG;

typedef enum
{
    ENC, //
    DEC
} SSL_OP;

typedef enum
{
    GCM, //
    CTR
} AES_ALGO;

#ifdef __cplusplus
extern "C"
{
#endif

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

    void read_encrypt_write(char *file_in, char *file_out, int max_bytes);
    void read_decrypt(char *file_in, int max_bytes);

    void file_encrypt(int max_bytes);
    void file_decrypt(int max_bytes);

    

    void test_crypto();

#ifdef __cplusplus
}
#endif

#endif /* ENCRYPT_H */