/* identity.c -- Identity ("no-op") cipher.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: identity.c,v 1.2 2001/09/23 13:30:08 eelco Exp $

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

#include "identity.h"


static CipherResult identityExpandKey(Key * pKey)
{
   return CIPHERRC_OK;
}


static void identityFreeExpandedKey(Key * pKey)
{
}


static void identityEncryptBlock(Key * pKey,
   octet * pabBlock)
{
}


static void identityDecryptBlock(Key * pKey,
   octet * pabBlock)
{
}


static CipherSize aIdentitySizes[] = {
   { 8, 0 },
   { 0, 0 }
};

Cipher cipherIdentity =
{
   "none",
   "Identity block cipher",
   aIdentitySizes,
   identityExpandKey,
   identityFreeExpandedKey,
   identityEncryptBlock,
   identityDecryptBlock
};
