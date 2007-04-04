/* sha512.c
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


#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#include "sha512.h"
#include "logging.h"


#define Ch(x,y,z)   ((x & y) ^ (~x & z))
#define Maj(x,y,z)  ((x & y) ^ (x & z) ^ (y & z))
#define e0(x)       (RORuns64(x,28) ^ RORuns64(x,34) ^ RORuns64(x,39))
#define e1(x)       (RORuns64(x,14) ^ RORuns64(x,18) ^ RORuns64(x,41))
#define s0(x)       (RORuns64(x,1)  ^ RORuns64(x,8)  ^ (x >> 7))
#define s1(x)       (RORuns64(x,19) ^ RORuns64(x,61) ^ (x >> 6))

#define H0         0x6a09e667f3bcc908LL
#define H1         0xbb67ae8584caa73bLL
#define H2         0x3c6ef372fe94f82bLL
#define H3         0xa54ff53a5f1d36f1LL
#define H4         0x510e527fade682d1LL
#define H5         0x9b05688c2b3e6c1fLL
#define H6         0x1f83d9abfb41bd6bLL
#define H7         0x5be0cd19137e2179LL


#define LOAD_OP(I) {\
	t1  = input[(8*I)  ] & 0xff;   t1<<=8;\
	t1 |= input[(8*I)+1] & 0xff;   t1<<=8;\
	t1 |= input[(8*I)+2] & 0xff;   t1<<=8;\
	t1 |= input[(8*I)+3] & 0xff;   t1<<=8;\
	t1 |= input[(8*I)+4] & 0xff;   t1<<=8;\
	t1 |= input[(8*I)+5] & 0xff;   t1<<=8;\
	t1 |= input[(8*I)+6] & 0xff;   t1<<=8;\
	t1 |= input[(8*I)+7] & 0xff;\
	W[I] = t1;\
}
#define BLEND_OP(I) W[I  ] = s1(W[I-2]) + W[I-7] + s0(W[I-15]) + W[I-16];

void sha512_xform(u_int64_t *state, const u_char *input) {
	u_int64_t a,b,c,d,e,f,g,h, t1, t2;
	u_int64_t W[80];

	/* load the input */
	LOAD_OP(0); LOAD_OP(1); LOAD_OP( 2); LOAD_OP( 3); LOAD_OP( 4); LOAD_OP( 5); LOAD_OP( 6); LOAD_OP( 7);
	LOAD_OP(8); LOAD_OP(9); LOAD_OP(10); LOAD_OP(11); LOAD_OP(12); LOAD_OP(13); LOAD_OP(14); LOAD_OP(15);

	/* now blend */
	BLEND_OP(16); BLEND_OP(17); BLEND_OP(18); BLEND_OP(19); BLEND_OP(20); BLEND_OP(21); BLEND_OP(22); BLEND_OP(23);
	BLEND_OP(24); BLEND_OP(25); BLEND_OP(26); BLEND_OP(27); BLEND_OP(28); BLEND_OP(29); BLEND_OP(30); BLEND_OP(31);
	BLEND_OP(32); BLEND_OP(33); BLEND_OP(34); BLEND_OP(35); BLEND_OP(36); BLEND_OP(37); BLEND_OP(38); BLEND_OP(39);
	BLEND_OP(40); BLEND_OP(41); BLEND_OP(42); BLEND_OP(43); BLEND_OP(44); BLEND_OP(45); BLEND_OP(46); BLEND_OP(47);
	BLEND_OP(48); BLEND_OP(49); BLEND_OP(50); BLEND_OP(51); BLEND_OP(52); BLEND_OP(53); BLEND_OP(54); BLEND_OP(55);
	BLEND_OP(56); BLEND_OP(57); BLEND_OP(58); BLEND_OP(59); BLEND_OP(60); BLEND_OP(61); BLEND_OP(62); BLEND_OP(63);
	BLEND_OP(64); BLEND_OP(65); BLEND_OP(66); BLEND_OP(67); BLEND_OP(68); BLEND_OP(69); BLEND_OP(70); BLEND_OP(71);
	BLEND_OP(72); BLEND_OP(73); BLEND_OP(74); BLEND_OP(75); BLEND_OP(76); BLEND_OP(77); BLEND_OP(78); BLEND_OP(79);

	/* load the state into our registers */
	a=state[0];   b=state[1];   c=state[2];   d=state[3];  
	e=state[4];   f=state[5];   g=state[6];   h=state[7];  

	/* now iterate */
	t1 = h + e1(e) + Ch(e,f,g) + 0x428a2f98d728ae22ULL + W[ 0];    t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0x7137449123ef65cdULL + W[ 1];    t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0xb5c0fbcfec4d3b2fULL + W[ 2];    t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0xe9b5dba58189dbbcULL + W[ 3];    t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x3956c25bf348b538ULL + W[ 4];    t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0x59f111f1b605d019ULL + W[ 5];    t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x923f82a4af194f9bULL + W[ 6];    t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0xab1c5ed5da6d8118ULL + W[ 7];    t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0xd807aa98a3030242ULL + W[ 8];    t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0x12835b0145706fbeULL + W[ 9];    t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0x243185be4ee4b28cULL + W[10];    t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0x550c7dc3d5ffb4e2ULL + W[11];    t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x72be5d74f27b896fULL + W[12];    t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0x80deb1fe3b1696b1ULL + W[13];    t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x9bdc06a725c71235ULL + W[14];    t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0xc19bf174cf692694ULL + W[15];    t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0xe49b69c19ef14ad2ULL + W[16];    t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0xefbe4786384f25e3ULL + W[17];    t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0x0fc19dc68b8cd5b5ULL + W[18];    t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0x240ca1cc77ac9c65ULL + W[19];    t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x2de92c6f592b0275ULL + W[20];    t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0x4a7484aa6ea6e483ULL + W[21];    t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x5cb0a9dcbd41fbd4ULL + W[22];    t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0x76f988da831153b5ULL + W[23];    t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0x983e5152ee66dfabULL + W[24];    t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0xa831c66d2db43210ULL + W[25];    t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0xb00327c898fb213fULL + W[26];    t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0xbf597fc7beef0ee4ULL + W[27];    t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0xc6e00bf33da88fc2ULL + W[28];    t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0xd5a79147930aa725ULL + W[29];    t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x06ca6351e003826fULL + W[30];    t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0x142929670a0e6e70ULL + W[31];    t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0x27b70a8546d22ffcULL + W[32];    t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0x2e1b21385c26c926ULL + W[33];    t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0x4d2c6dfc5ac42aedULL + W[34];    t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0x53380d139d95b3dfULL + W[35];    t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x650a73548baf63deULL + W[36];    t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0x766a0abb3c77b2a8ULL + W[37];    t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x81c2c92e47edaee6ULL + W[38];    t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0x92722c851482353bULL + W[39];    t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0xa2bfe8a14cf10364ULL + W[40];    t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0xa81a664bbc423001ULL + W[41];    t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0xc24b8b70d0f89791ULL + W[42];    t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0xc76c51a30654be30ULL + W[43];    t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0xd192e819d6ef5218ULL + W[44];    t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0xd69906245565a910ULL + W[45];    t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0xf40e35855771202aULL + W[46];    t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0x106aa07032bbd1b8ULL + W[47];    t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0x19a4c116b8d2d0c8ULL + W[48];    t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0x1e376c085141ab53ULL + W[49];    t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0x2748774cdf8eeb99ULL + W[50];    t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0x34b0bcb5e19b48a8ULL + W[51];    t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x391c0cb3c5c95a63ULL + W[52];    t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0x4ed8aa4ae3418acbULL + W[53];    t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x5b9cca4f7763e373ULL + W[54];    t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0x682e6ff3d6b2b8a3ULL + W[55];    t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0x748f82ee5defb2fcULL + W[56];    t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0x78a5636f43172f60ULL + W[57];    t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0x84c87814a1f0ab72ULL + W[58];    t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0x8cc702081a6439ecULL + W[59];    t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x90befffa23631e28ULL + W[60];    t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0xa4506cebde82bde9ULL + W[61];    t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0xbef9a3f7b2c67915ULL + W[62];    t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0xc67178f2e372532bULL + W[63];    t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0xca273eceea26619cULL + W[64];    t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0xd186b8c721c0c207ULL + W[65];    t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0xeada7dd6cde0eb1eULL + W[66];    t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0xf57d4f7fee6ed178ULL + W[67];    t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x06f067aa72176fbaULL + W[68];    t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0x0a637dc5a2c898a6ULL + W[69];    t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x113f9804bef90daeULL + W[70];    t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0x1b710b35131c471bULL + W[71];    t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0x28db77f523047d84ULL + W[72];    t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0x32caab7b40c72493ULL + W[73];    t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0x3c9ebe0a15c9bebcULL + W[74];    t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0x431d67c49c100d4cULL + W[75];    t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x4cc5d4becb3e42b6ULL + W[76];    t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0x597f299cfc657e2aULL + W[77];    t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x5fcb6fab3ad6faecULL + W[78];    t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0x6c44198c4a475817ULL + W[79];    t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	state[0]+=a;   state[1]+=b;   state[2]+=c;   state[3]+=d;  
	state[4]+=e;   state[5]+=f;   state[6]+=g;   state[7]+=h;  
}


void sha512_init(sha512_context *C) {
	C->state[0] = H0;
	C->state[1] = H1;
	C->state[2] = H2;
	C->state[3] = H3;
	C->state[4] = H4;
	C->state[5] = H5;
	C->state[6] = H6;
	C->state[7] = H7;
	C->count[0] = C->count[1] = C->count[2] = C->count[3] = 0;
	memset(C->buf, 0, 128);
}


void sha512_update(sha512_context *C, u_char *input, unsigned int inputLen) {
	u_int32_t i, index, partLen;

	/* Compute number of bytes mod 128 */
	index = (u_int32_t)((C->count[0] >> 3) & 0x7F);

	/* Update number of bits */
	if ((C->count[0] += (inputLen << 3)) < (inputLen << 3)) {
		if ((C->count[1] += 1) < 1)
		if ((C->count[2] += 1) < 1)
		C->count[3]++;
		C->count[1] += (inputLen >> 29);
	}

	partLen = 128 - index;

	/* Transform as many times as possible. */
	if (inputLen >= partLen) {
		memcpy((u_char*)&C->buf[index], input, partLen);
		sha512_xform(C->state, C->buf);

		for (i=partLen; i+127<inputLen; i+=128)
		sha512_xform(C->state, &input[i]);

		index = 0;
	} else {
		i = 0;
	}

	/* Buffer remaining input */
	memcpy((u_char*)&C->buf[index], (u_char*)&input[i], inputLen-i);
}

void sha512_final(u_char *digest, sha512_context *C) {
	u_char bits[128], padding[128];
	u_int32_t index, padLen;
	u_int32_t t;
	u_int64_t t2;
	int i,j;

	memset(bits, 0, 128);
	memset(padding, 0, 128);
	padding[0] = 0x80;

	/* Save number of bits */
	t = C->count[0];
	bits[15] = t; t>>=8;
	bits[14] = t; t>>=8;
	bits[13] = t; t>>=8;
	bits[12] = t; t>>=8;
	t = C->count[1];
	bits[11] = t; t>>=8;
	bits[10] = t; t>>=8;
	bits[9 ] = t; t>>=8;
	bits[8 ] = t; t>>=8;
	t = C->count[2];
	bits[7 ] = t; t>>=8;
	bits[6 ] = t; t>>=8;
	bits[5 ] = t; t>>=8;
	bits[4 ] = t; t>>=8;
	t = C->count[3];
	bits[3 ] = t; t>>=8;
	bits[2 ] = t; t>>=8;
	bits[1 ] = t; t>>=8;
	bits[0 ] = t; t>>=8;

	/* Pad out to 112 mod 128. */
	index = (C->count[0] >> 3) & 0x7f;
	padLen = (index < 112) ? (112 - index) : ((128+112) - index);
	sha512_update(C, (u_char*)padding, padLen);

	/* Append length (before padding) */
	sha512_update(C, bits, 16);

	/* Store state in digest */
	for (i=j=0; i<8; i++,j+=8) {
		t2 = C->state[i];
		digest[j+7] = (char)t2 & 0xff; t2>>=8;
		digest[j+6] = (char)t2 & 0xff; t2>>=8;
		digest[j+5] = (char)t2 & 0xff; t2>>=8;
		digest[j+4] = (char)t2 & 0xff; t2>>=8;
		digest[j+3] = (char)t2 & 0xff; t2>>=8;
		digest[j+2] = (char)t2 & 0xff; t2>>=8;
		digest[j+1] = (char)t2 & 0xff; t2>>=8;
		digest[j  ] = (char)t2 & 0xff;
	}

	/* Zeroize sensitive information. */
	memset(C, 0, sizeof(sha512_context));
}


void sha512(u_char *message, u_int32_t len, u_char *digest) {
	sha512_context ctx;

	sha512_init(&ctx);
	sha512_update(&ctx, message, len);
	sha512_final(digest, &ctx);
}


char *mem_sha512sum(u_char *msg, u_int32_t len) {
        u_char	sha512_result[512];
	char	*sha512sum, *ptr;
	int	i;

        sha512(msg ,len, sha512_result);

	/* allocate memory for sha512sum string */
	if(!(sha512sum = (char *) calloc(128 + 1, 1))) {
		logmsg(LOG_ERR, 1, "Error - Can't allocate memory for sha512 checksum string.\n");
		return(NULL);
	}
	bzero(sha512sum,129);
	ptr = sha512sum;
        for(i = 0; i < 64; i++) {
                *ptr = ((sha512_result[i] >> 4) < 10 ? (sha512_result[i] >> 4) + '0' : (sha512_result[i] >> 4) + ('a' - 10));
		++ptr;
                *ptr = ((sha512_result[i] & 0xf) < 10 ? (sha512_result[i] & 0xf) + '0' : (sha512_result[i] & 0xf) + ('a' - 10));
		++ptr;
        }
        return(sha512sum);
}
