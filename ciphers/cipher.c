/* cipher.c -- Key creation and destruction.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: cipher.c,v 1.3 2001/09/23 13:30:08 eelco Exp $

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

#include "cipher.h"
#include "sysdep.h"


CipherResult cryptCreateKey(Cipher * pCipher, 
   unsigned int cbBlock, unsigned int cbKey, octet * pabKey,
   Key * * ppKey)
{
   Key * pKey;
   CipherResult cr;
   
   *ppKey = 0;

   /* Make the cipher instance. */
   pKey = sysAllocSecureMem(sizeof(Key));
   if (!pKey)
      return CIPHERRC_NOT_ENOUGH_MEMORY;

   pKey->pCipher = pCipher;
   pKey->cbBlock = cbBlock;
   pKey->cbKey = cbKey;

   pKey->pabKey = sysAllocSecureMem(cbKey);
   if (!pKey->pabKey) {
      sysFreeSecureMem(pKey);
      return CIPHERRC_NOT_ENOUGH_MEMORY;
   }
   memcpy(pKey->pabKey, pabKey, cbKey);

   /* Do key expansion. */
   cr = pCipher->expandKey(pKey);
   if (cr) {
      sysFreeSecureMem(pKey->pabKey);
      sysFreeSecureMem(pKey);
      return cr;
   }

   *ppKey = pKey;

   return CIPHERRC_OK;
}


void cryptDestroyKey(Key * pKey)
{
   /* Free the key expansion stuff. */
   pKey->pCipher->freeExpandedKey(pKey);

   /* Free the key. */
   sysFreeSecureMem(pKey->pabKey);

   /* Free the cipher instance. */
   sysFreeSecureMem(pKey);
}
