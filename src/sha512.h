/* sha512.h
 * Copyright (C) 2007 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * This code is based on the SHA-512 code by Jean-Luc Cooke <jlcooke@certainkey.com>
 */


#ifndef SHA512_H
#define SHA512_H

#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>


#define ROLuns64(a,b) ( ((a) << ((b) & 63)) | ((a) >> (64-((b) & 63))) )
#define RORuns64(a,b) ( ((a) >> ((b) & 63)) | ((a) << (64-((b) & 63))) )


typedef struct {
  u_int64_t	state[8];
  u_char	buf[128];
  u_int32_t	count[4];
} sha512_context;


extern void sha512_init(sha512_context *c);
extern void sha512_update(sha512_context *c, u_char *input, unsigned int inLen);
extern void sha512_final(u_char *digest, sha512_context *c);

char *mem_sha512sum(u_char *msg, u_int32_t len);

#endif
