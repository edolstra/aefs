/* superblock.c -- Superblock code.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: superblock.c,v 1.10 2001/09/23 13:30:11 eelco Exp $

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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>

#include "sysdep.h"
#include "superblock.h"
#include "sha.h"


static CoreResult cipherResultToCore(CipherResult cr)
{
   switch (cr) {
      case CIPHERRC_OK:
         return CORERC_OK;
      case CIPHERRC_NOT_ENOUGH_MEMORY:
         return CORERC_NOT_ENOUGH_MEMORY;
      case CIPHERRC_UNKNOWN_CIPHER:
         return CORERC_UNKNOWN_CIPHER;
      default:
         return CORERC_MISC_CIPHER;
   }
}


/* Hash an variable-length (zero-terminated) key phrase into a
   fixed-length key of cbKey bytes.  We do this using the SHA.
   The method is as follows.  The key is initialized to 0.  Then,
   while there are bytes left in the key phrase, we do the following.
   We take at most the first 20 bytes (the SHA digest length).
   We calculate the SHA hash value of the concatenation of the current
   key and the partial key phrase.  We then cyclically XOR the current
   key with the hash value, yielding the key.
   
   Rationale: the hash function should be such that a) no entropy in
   the key phrase is "wasted"; b) even if the input alphabet is
   constrained, the resulting keyspace should not be constrained.

   The reason that we SHA-hash not just the partial key phrase but
   also the current key is to prevent repetitions in the key phrase
   from carrying over into the key.  For example, if the key length is
   20 bytes, then the key phrase consisting of 20 times the letter 'x'
   will yield the same key as the key phrase consisting of 60 times
   the letter 'x' (and the key resulting from 40 times the letter 'x'
   would be 0 due to X xor X = 0).  Of course, a repetitious key
   phrase is not a good idea anyway, but otherwise criterium (a) would
   be violated.

   Note that if the key phrase is smaller than the key, only the first
   cbKey (rounded up to a multiple of 20) key bytes are
   initialized to values based upon the key phrase.  The other remain
   zero.  Problem? */
CoreResult coreHashKey(char * pszKey, octet * pabKey, 
   unsigned int cbKey)
{
   struct sha_ctx ctx;
   unsigned int iPos = 0, cbLeft, cbAdd, i;
   octet digest[SHA_DIGESTSIZE];

   memset(pabKey, 0, cbKey);

   cbLeft = strlen(pszKey);

   while (cbLeft > 0) {
      cbAdd = cbLeft >= SHA_DIGESTSIZE ? SHA_DIGESTSIZE : cbLeft;

      sha_init(&ctx);
      sha_update(&ctx, pabKey, cbKey);
      sha_update(&ctx, (octet *) pszKey, cbAdd);
      sha_final(&ctx);
      sha_digest(&ctx, digest);

      for (i = 0; i < SHA_DIGESTSIZE; i++) {
         pabKey[iPos++] ^= digest[i];
         if (iPos == cbKey) iPos = 0;
      }
      
      pszKey += cbAdd;
      cbLeft -= cbAdd;
   }
   
   return CORERC_OK;
}


/* Read info about the cipher and flags (i.e. CBC mode) used for this
   volume.  Create a key instance. */
static CoreResult readSuperBlock1(SuperBlock * pSuperBlock,
   char * pszKey, CryptedVolumeParms * pParms, Cipher * * papCipher)
{
   CoreResult cr;
   SysResult sr;
   CipherResult cr2;
   char szFileName[MAX_VOLUME_BASE_PATH_NAME + 128];
   File * pFile;
   char szFile[1025], * pszCur, * pszNext, szName[256], szValue[256];
   char szCipher[64] = "";
   FilePos cbRead;
   unsigned int cbKey = 0, cbBlock = 0;
   octet abKey[MAX_KEY_SIZE];

   /* Read the unencrypted superblock. */
   
   if (snprintf(szFileName, sizeof(szFileName), "%s" SUPERBLOCK1_NAME,
      pSuperBlock->pszBasePath) >= sizeof(szFileName))
      return CORERC_INVALID_PARAMETER;

   sr = sysOpenFile(szFileName,
      SOF_READONLY | SOF_DENYNONE,
      pParms->cred, &pFile);
   if (sr) return sys2core(sr);

   if (sr = sysReadFromFile(pFile, sizeof(szFile) - 1, 
      (octet *) szFile, &cbRead))
   {
      sysCloseFile(pFile);
      return sys2core(sr);
   }
   szFile[cbRead] = 0;

   sysCloseFile(pFile);
   
   pszCur = szFile;
   while (*pszCur) {

      pszNext = pszCur;
      while (*pszNext && *pszNext != '\r' && *pszNext != '\n') pszNext++;
      if (*pszNext) *pszNext++ = 0;

      if (sscanf(pszCur, "%100[^:]: %100s\n", szName, szValue) == 2) {
         if (strcmp(szName, "cipher") == 0) {
            if (sscanf(szValue, "%63[^-]-%d-%d", szCipher,
               &cbKey, &cbBlock) == 3)
            {
               cbBlock /= 8;
               cbKey /= 8;
            }
         } else if (strcmp(szName, "use-cbc") == 0) {
            if (strcmp(szValue, "1") == 0)
               pParms->flCryptoFlags |= CCRYPT_USE_CBC;
            else
               pParms->flCryptoFlags &= ~CCRYPT_USE_CBC;
         }
      }
       
      pszCur = pszNext;
   }
   
   /* Do we know the specified cipher? */
   while (*papCipher) {
      if (strcmp((*papCipher)->pszID, szCipher) == 0)
         break;
      papCipher++;
   }
   if (!*papCipher) return CORERC_UNKNOWN_CIPHER;

   /* Hash the user's key string into the cbKey-bytes wide key
      expected by the cipher. */
   cr = coreHashKey(pszKey, abKey, cbKey);
   if (cr) return cr;

   /* Construct a cipher instance (key). */
   cr2 = cryptCreateKey(*papCipher,
      cbBlock, cbKey, abKey, &pSuperBlock->pKey);
   memset(abKey, 0, MAX_KEY_SIZE); /* burn */
   if (cr2) return cipherResultToCore(cr2);

   return CORERC_OK;
}


/* Open the encrypted superblock file. */
static CoreResult openSuperBlock2(SuperBlock * pSuperBlock,
   CryptedVolumeParms * pParms, bool fCreate)
{
   SysResult sr;
   char szFileName[MAX_VOLUME_BASE_PATH_NAME + 128];

   if (pSuperBlock->pSB2File) return CORERC_OK;

   if (snprintf(szFileName, sizeof(szFileName), "%s" SUPERBLOCK2_NAME,
      pSuperBlock->pszBasePath) >= sizeof(szFileName))
      return CORERC_INVALID_PARAMETER;

   sr = sysOpenFile(szFileName,
      (fCreate ? SOF_CREATE_IF_NEW : 0) | 
      (pParms->fReadOnly 
         ? SOF_READONLY | SOF_DENYWRITE
         : SOF_READWRITE | SOF_DENYALL),
      pParms->cred, &pSuperBlock->pSB2File);
   if (sr) return sys2core(sr);

   return CORERC_OK;
}


/* Read the info in the encrypted superblock file into pSuperBlock. */
static CoreResult readSuperBlock2(SuperBlock * pSuperBlock,
   CryptedVolumeParms * pParms)
{
   CoreResult cr;
   SysResult sr;
   FilePos cbRead;
   octet abSector[SECTOR_SIZE];
   CryptedSectorData sector;
   SuperBlock2OnDisk * pOnDisk =
      (SuperBlock2OnDisk *) &sector.payload;

   cr = openSuperBlock2(pSuperBlock, pParms, false);
   if (cr) return cr;

   if (sr = sysSetFilePos(pSuperBlock->pSB2File, 0)) 
       return sys2core(sr);
   
   if (sr = sysReadFromFile(pSuperBlock->pSB2File, sizeof(abSector),
       abSector, &cbRead)) 
      return sys2core(sr);
   
   cr = coreDecryptSectorData(abSector, &sector,
      pSuperBlock->pKey, pParms->flCryptoFlags);
   
   pSuperBlock->magic = bytesToInt32(pOnDisk->magic);
   pSuperBlock->version = bytesToInt32(pOnDisk->version);
   pSuperBlock->flFlags = bytesToInt32(pOnDisk->flFlags);
   pSuperBlock->idRoot = bytesToInt32(pOnDisk->idRoot);
   memcpy(pSuperBlock->szLabel, pOnDisk->szLabel,
      sizeof(pSuperBlock->szLabel));
   pSuperBlock->szLabel[sizeof(pSuperBlock->szLabel) - 1] = 0;
   memcpy(pSuperBlock->szDescription, pOnDisk->szDescription,
      sizeof(pSuperBlock->szDescription));
   pSuperBlock->szDescription[sizeof(pSuperBlock->szDescription) - 1] = 0;

   memset(&sector, 0, sizeof(sector)); /* burn */
   
   return cr;
}


static CoreResult createVolume(SuperBlock * pSuperBlock,
   CryptedVolumeParms * pParms)
{
   return coreAccessVolume(
      pSuperBlock->pszBasePath,
      pSuperBlock->pKey,
      pParms,
      &pSuperBlock->pVolume);
}


CoreResult coreReadSuperBlock(char * pszBasePath, char * pszKey,
   Cipher * * papCipher, CryptedVolumeParms * pParms,
   SuperBlock * * ppSuperBlock)
{
   CoreResult cr, crread2;
   SuperBlock * pSuperBlock;

   /* Sanity checks. */
   assert(sizeof(SuperBlock2OnDisk) <= PAYLOAD_SIZE);

   *ppSuperBlock = 0;

   pSuperBlock = sysAllocSecureMem(sizeof(SuperBlock) +
      strlen(pszBasePath) + 1);
   if (!pSuperBlock) return CORERC_NOT_ENOUGH_MEMORY;

   pSuperBlock->pszBasePath = sizeof(SuperBlock) +
      (char *) pSuperBlock;
   strcpy(pSuperBlock->pszBasePath, pszBasePath);
   pSuperBlock->pSB2File = 0;

   if (cr = readSuperBlock1(pSuperBlock, pszKey, pParms, papCipher)) {
      sysFreeSecureMem(pSuperBlock);
      return cr;
   }

   /* It's not a fatal error if the encrypted part of the superblock
      is missing (this is mostly so that aefsck can reconstruct
      partially broken superblocks). */
   crread2 = readSuperBlock2(pSuperBlock, pParms);

   if (cr = createVolume(pSuperBlock, pParms)) {
      sysFreeSecureMem(pSuperBlock);
      return cr;
   }

   *ppSuperBlock = pSuperBlock;

   if (crread2) return crread2;
   if (pSuperBlock->magic != SUPERBLOCK2_MAGIC)
      return CORERC_BAD_SUPERBLOCK;
   /* Only fail if the major version number has changed. */
   if (pSuperBlock->version & 0xff0000 > SBV_CURRENT & 0xff0000)
      return CORERC_BAD_VERSION;
   return CORERC_OK;
}


CoreResult coreWriteSuperBlock(SuperBlock * pSuperBlock, 
   unsigned int flags)
{
   char szFileName[MAX_VOLUME_BASE_PATH_NAME + 128], szBuffer[1024];
   File * pFile;
   CryptedSectorData sector;
   SuperBlock2OnDisk * pOnDisk =
      (SuperBlock2OnDisk *) &sector.payload;
   FilePos cbWritten;
   CryptedVolumeParms * pParms =
      coreQueryVolumeParms(pSuperBlock->pVolume);
   SysResult sr;
   CoreResult cr;

   if (pParms->fReadOnly) return CORERC_READ_ONLY;

   if (!(flags & CWS_NOWRITE_SUPERBLOCK1)) {
      
      /* Write the unencrypted part of the superblock. */

      if (snprintf(szBuffer, sizeof(szBuffer),
         "cipher: %s-%d-%d\n"
         "use-cbc: %d\n",
         pSuperBlock->pKey->pCipher->pszID,
         pSuperBlock->pKey->cbKey * 8,
         pSuperBlock->pKey->cbBlock * 8,
         pParms->flCryptoFlags & CCRYPT_USE_CBC) >= sizeof(szBuffer))
         return CORERC_INVALID_PARAMETER;
      
      if (snprintf(szFileName, sizeof(szFileName), "%s" SUPERBLOCK1_NAME,
         pSuperBlock->pszBasePath) >= sizeof(szFileName))
         return CORERC_INVALID_PARAMETER;

      sr = sysOpenFile(szFileName,
         SOF_CREATE_IF_NEW | SOF_TRUNC_IF_EXISTS |
         SOF_READWRITE | SOF_DENYALL,
         pParms->cred, &pFile);
      if (sr) return sys2core(sr);

      if (sr = sysWriteToFile(pFile, strlen(szBuffer), 
         (octet *) szBuffer, &cbWritten))
      {
         sysCloseFile(pFile);
         return sys2core(sr);
      }
      
      sysCloseFile(pFile);
   }

   /* Write the encrypted part of the superblock. */

   memset(sector.payload, 0, sizeof(sector.payload));

   sysGetRandomBits(sizeof(sector.random) * 8, sector.random);

   int32ToBytes(SUPERBLOCK2_MAGIC, pOnDisk->magic);
   int32ToBytes(SBV_CURRENT, pOnDisk->version);
   int32ToBytes(pSuperBlock->flFlags, pOnDisk->flFlags);
   int32ToBytes(pSuperBlock->idRoot, pOnDisk->idRoot);
   strcpy((char *) pOnDisk->szLabel, pSuperBlock->szLabel);
   strcpy((char *) pOnDisk->szDescription, pSuperBlock->szDescription);
   
   coreEncryptSectorData(&sector, (octet *) &sector,
      pSuperBlock->pKey, pParms->flCryptoFlags);

   cr = openSuperBlock2(pSuperBlock, pParms, true);
   if (cr) return cr;

   if (sr = sysSetFilePos(pSuperBlock->pSB2File, 0)) 
       return sys2core(sr);
   
   if (sr = sysWriteToFile(pSuperBlock->pSB2File, 
       sizeof(sector), (octet *) &sector, &cbWritten))
       return sys2core(sr);

   pSuperBlock->version = SBV_CURRENT;
   pSuperBlock->magic = SUPERBLOCK2_MAGIC;

   return CORERC_OK;
}


CoreResult coreDropSuperBlock(SuperBlock * pSuperBlock)
{
   CoreResult cr;
   
   cr = coreDropVolume(pSuperBlock->pVolume);
   if (cr) return cr;

   if (pSuperBlock->pSB2File)
       sysCloseFile(pSuperBlock->pSB2File);

   cryptDestroyKey(pSuperBlock->pKey);

   sysFreeSecureMem(pSuperBlock);

   return CORERC_OK;
}
