/*
 * sha512.c
 *
 * packet payload hash computation
 *
 * Stand alone compilation:
 * gcc sha512.c -lcrypto
 *
 */
#include <stdio.h>
#include <openssl/sha.h>
#include <string.h>

#include "sha512.h"

int sha512(const char *data, unsigned char *digest){
    unsigned char byte_digest[SHA512_DIGEST_LENGTH];

    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, data, strlen(data));
    SHA512_Final(byte_digest, &sha512);

    int i = 0; 
    for(i=0; i<SHA512_DIGEST_LENGTH; i++){
        sprintf((char*)digest + i*2, "%02x", byte_digest[i]);
    }
    return 1;
}
