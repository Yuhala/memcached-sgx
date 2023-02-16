/*
 * Created on Wed Feb 15 2023
 *
 * Copyright (c) 2023 Peterson Yuhala
 */

// #include <openssl/conf.h>
// #include <openssl/evp.h>
// #include <openssl/err.h>
// #include <string.h>
// #include <stdlib.h>
// #include <stdio.h>
// #include <sys/types.h>
// #include <unistd.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#include "Enclave.h"
#include "encrypt.h"

#define NODEBUG 0
#define TMPINFO 1
#define INFO 2
#define INFOENC 2
#define INFOREADWRITE 3
#define VERBOSE 4
#define VVERBOSE 5
#define MISS 6
#define ALL 7

#define ISDEBUG NODEBUG

#define AES_BLOCK_SIZE 16
#define HASH_SIZE 32
#define AES_KEY_SIZE 32

#define CHUNK_DISK_SIZE 4096
#define CHUNK_DATA_SIZE_BYTES (CHUNK_DISK_SIZE - AES_BLOCK_SIZE - HASH_SIZE) // 4KB 4080 - 32 = 4048 // 4096-32 = 4064

// /* A 256 bit key */
// char *key = (char *)"01234567890123456789012345678901";

/* A 128 bit IV */
// char *iv = (char *)"0123456789012345";
uint8_t constiv[] = {0x01, 0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
uint8_t const_key[] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

uint8_t *hash_bytes;
// char *enc_filename="datax_enc.csv";
// char *dec_filename="datax_dec.csv";

char *enc_filename = "/home/ubuntu/memcached-sgx/sgx/ciphertext.txt";
char *dec_filename = "/home/ubuntu/memcached-sgx/sgx/clairtext.txt";

int encrypt(unsigned char *plaintext,
            int plaintext_len,
            unsigned char *key,
            unsigned char *iv,
            unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        handleErrors();
    }

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        handleErrors();
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        handleErrors();
    }
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        handleErrors();
    }
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext,
            int ciphertext_len,
            unsigned char *key,
            unsigned char *iv,
            unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        handleErrors();
    }

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        handleErrors();
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        handleErrors();
    }
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        handleErrors();
    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

void handleErrors(void)
{
    //ERR_print_errors_fp(stderr);
    abort();
}

void test_crypto ()
{
    /* Load the human readable error strings for libcrypto */
    //ERR_load_crypto_strings();
    printf(">>>> 1 >>>>\n");

    /* Load all digest and cipher algorithms */
    //OpenSSL_add_all_algorithms();


    /* Load config file, and other important initialisation */
    // OPENSSL_config(NULL);
    //OPENSSL_no_config();
     printf(">>>> 2 >>>>\n");

    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    unsigned char *iv = (unsigned char *)"someIV";
    unsigned char *plaintext = (unsigned char *)"Hello Peterson";
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];

    int decryptedtext_len = 0;
    int ciphertext_len = 0;
    ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext);
    printf("Ciphertext is:\n");
    //BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
    decryptedtext[decryptedtext_len] = '\0';
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);

    /* Removes all digests and ciphers */
    EVP_cleanup();

    /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
    CRYPTO_cleanup_all_ex_data();

    /* Remove error strings */
    ERR_free_strings();
}
