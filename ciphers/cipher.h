/* cipher.c -- Defines cipher and key structures.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: cipher.h,v 1.3 2001/09/23 13:30:08 eelco Exp $

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#ifndef _CIPHER_H
#define _CIPHER_H

#include "types.h"


#define MAX_BLOCK_SIZE 64 /* bytes */
#define MAX_KEY_SIZE   64 /* bytes */


/* Error codes. */

typedef unsigned int CipherResult;

#define CIPHERRC_OK                  0
#define CIPHERRC_NOT_ENOUGH_MEMORY   1
#define CIPHERRC_UNKNOWN_CIPHER      2
#define CIPHERRC_INVALID_KEYSIZE     3
#define CIPHERRC_INVALID_BLOCKSIZE   4


/* Types. */

typedef struct _Cipher Cipher;
typedef struct _Key Key;

typedef CipherResult (* ExpandKey)(Key * pKey);
typedef void (* FreeExpandedKey)(Key * pKey);
typedef void (* EncryptBlock)(Key * pKey,
   octet * pabBlock);
typedef void (* DecryptBlock)(Key * pKey,
   octet * pabBlock);

typedef struct {
      unsigned int cbBlock, cbKey; /* block & key size in bytes */
} CipherSize;

struct _Cipher {
      char *          pszID;
      char *          pszDescription;

      /* Array of suggested block and key sizes.  The cipher may
         accept others than those listed in this table.  The array is
         terminated by an entry with cbBlock zero.  The first element
         of the array specifies the default block and key size. */
      CipherSize *    paSizes;

      ExpandKey       expandKey;
      FreeExpandedKey freeExpandedKey;
      EncryptBlock    encryptBlock;
      DecryptBlock    decryptBlock;
};

struct _Key {
      Cipher * pCipher;

      unsigned int cbBlock;
      unsigned int cbKey;

      octet * pabKey;
      void * pExpandedKey;
};


/* Functions. */

CipherResult cryptCreateKey(Cipher * pCipher, 
   unsigned int cbBlock, unsigned int cbKey, octet * pabKey,
   Key * * ppKey);

void cryptDestroyKey(Key * pKey);


#endif /* !_CIPHER_H */
