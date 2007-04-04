/* md5.h
 * Copyright (C) 2005 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * This code is based on an OpenSSL-compatible implementation of the RSA
 * Data Security, * Inc. MD5 Message-Digest Algorithm, written by Solar
 * Designer <solar at openwall.com> in 2001, and placed in the public
 * domain. There's absolutely no warranty. See md5.c for more information.
 */

#ifndef __HONEYTRAP_MD5_H
#define __HONEYTRAP_MD5_H

/* Any 32-bit or wider unsigned integer data type will do */
typedef unsigned long MD5_u32plus;

typedef struct {
	MD5_u32plus lo, hi;
	MD5_u32plus a, b, c, d;
	unsigned char buffer[64];
	MD5_u32plus block[16];
} MD5_CTX;

extern void MD5_Init(MD5_CTX *ctx);
extern void MD5_Update(MD5_CTX *ctx, void *data, unsigned long size);
extern void MD5_Final(unsigned char *result, MD5_CTX *ctx);
char *mem_md5sum(u_char *msg, u_int32_t size);

#endif
