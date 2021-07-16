/*
 * sha512.h
 *
 * header file for packet payload hash computation
 *
 */

#ifndef SHA512_H
#define SHA512_H

#include <openssl/sha.h>
#include <string.h>

int sha512(const char *data, unsigned char *digest);

#endif /*sha512.h*/
