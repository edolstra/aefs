/* $Id: std_defs.h,v 1.2 2000/12/29 23:06:11 eelco Exp $ */

#include "cipher.h"

/* Compatibility with AES cryptographic source code. */

typedef uint8  u1byte; /* an 8 bit unsigned character type */
typedef uint32 u4byte; /* a 32 bit unsigned integer type   */

#define rotr(x,n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
#define rotl(x,n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))

/* Extract byte from a 32 bit quantity (little endian notation)     */ 

#define byte(x,n)   ((u1byte)((x) >> (8 * n)))
