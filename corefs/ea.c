/* ea.c -- Extented attribute access and modification.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: ea.c,v 1.4 2001/09/23 13:30:11 eelco Exp $

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

#include <string.h>
#include <assert.h>

#include "corefs.h"
#include "sysdep.h"


CoreResult coreAllocEA(char * pszName, unsigned int cbValue, 
   unsigned int flFlags, CryptedEA * * ppEA)
{
   CryptedEA * pEA;
   unsigned int cbName = strlen(pszName);

   pEA = sysAllocSecureMem(sizeof(CryptedEA) + cbName + 1 +
      cbValue);
   if (!pEA) return CORERC_NOT_ENOUGH_MEMORY;

   pEA->pNext = 0;
   pEA->pszName = sizeof(CryptedEA) + (char *) pEA;
   pEA->cbValue = cbValue;
   pEA->pabValue = sizeof(CryptedEA) + cbName + 1 + (octet *) pEA;
   pEA->flFlags = flFlags;
   memcpy(pEA->pszName, pszName, cbName + 1);

   *ppEA = pEA;

   return CORERC_OK;
}


void coreFreeEAs(CryptedEA * pEAs)
{
   CryptedEA * pNext;
   for ( ; pEAs; pEAs = pNext) {
      pNext = pEAs->pNext;
      sysFreeSecureMem(pEAs);
   }
}


static CoreResult readExternalEAs(CryptedVolume * pVolume,
   CryptedFileID id, CryptedFileInfo * pInfo,
   unsigned int cbEAs, octet * pabEAs)
{
   CoreResult cr;
   CryptedFilePos cbRead;

   /* Verify that it is an EA file. */
   if (!CFF_ISEA(pInfo->flFlags)) return CORERC_BAD_TYPE;

   /* Read the file contents. */
   cr = coreReadFromFile(pVolume, id, 0, cbEAs, pabEAs, &cbRead);
   if (cr) return cr;

   return CORERC_OK;
}


static CoreResult readInternalEAs(CryptedVolume * pVolume,
   CryptedFileID id, unsigned int cbEAs, octet * pabEAs)
{
   CoreResult cr;

   /* Read the EAs from the file's info sector. */
   cr = coreQuerySectorData(pVolume, INFOSECTORFILE_ID,
      coreQueryInfoSectorNumber(pVolume, id),
      sizeof(CryptedFileInfoOnDisk) + FILEINFO_RESERVED, cbEAs,
      0, pabEAs);
   
   return CORERC_OK;
}


static CoreResult decodeEAs(unsigned int cbEAs, octet * pabEAs,
   CryptedEA * * ppEAs)
{
   CoreResult cr;
   unsigned int flFlags;
   char * pszName;
   unsigned int cbValue;
   octet * pabValue;
   
   /* Process the next EA until there are no bytes left or the header
      byte is 0 (= end of EAs). */
   while (cbEAs && *pabEAs) {

      flFlags = *pabEAs & ~CEF_NOT_EOL;

      cbEAs--, pabEAs++;

      /* Scan past the end of the EA name. */
      pszName = (char *) pabEAs;
      while (cbEAs && *pabEAs) cbEAs--, pabEAs++;
      if (cbEAs < 5) return CORERC_BAD_EAS;
      cbEAs--, pabEAs++;

      /* Get the length and start of the value. */
      cbValue = bytesToInt32(pabEAs);
      cbEAs -= 4, pabEAs += 4;
      pabValue = pabEAs;
      if (cbEAs < cbValue) return CORERC_BAD_EAS;
      cbEAs -= cbValue, pabEAs += cbValue;

      /* Create an EA structure. */
      cr = coreAllocEA(pszName, cbValue, flFlags, ppEAs);
      if (cr) return cr;
      memcpy((*ppEAs)->pabValue, pabValue, cbValue);
      ppEAs = &(*ppEAs)->pNext;
   }

   if (cbEAs != 1) return CORERC_BAD_EAS;

   return CORERC_OK;
}


static CoreResult getInfoAndVerify(CryptedVolume * pVolume,
   CryptedFileID id, CryptedFileInfo * pInfo)
{
   CoreResult cr;
   
   /* Get file info. */
   cr = coreQueryFileInfo(pVolume, id, pInfo);
   if (cr) return cr;

   /* Only regular files and directories can have EAs. */
   if (!CFF_ISREG(pInfo->flFlags) && !CFF_ISDIR(pInfo->flFlags))
      return CORERC_BAD_TYPE;

   return CORERC_OK;
}


CoreResult coreQueryEAs(CryptedVolume * pVolume,
   CryptedFileID id, CryptedEA * * ppEAs)
{
   CoreResult cr;
   CryptedFileInfo info, info2;
   octet * pabEAs;

   *ppEAs = 0;

   /* Get file info. */
   cr = getInfoAndVerify(pVolume, id, &info);
   if (cr) return cr;

   if (!info.cbEAs) return CORERC_OK;

   /* Sanity check.  Prevents us from allocating enormous amounts of
      memory in the case that the cbEAs field has been corrupted. */
   if (info.flFlags & CFF_EXTEAS) {
      
      cr = coreQueryFileInfo(pVolume, info.idEAFile, &info2);
      if (cr) return cr;

      if (info.cbEAs != info2.cbFileSize) return CORERC_BAD_EAS;

   } else {

      if (info.cbEAs > MAX_INTERNAL_EAS) return CORERC_BAD_EAS;

   }

   /* Allocate a buffer for the encoded EA data. */
   pabEAs = sysAllocSecureMem(info.cbEAs);
   if (!pabEAs) return CORERC_NOT_ENOUGH_MEMORY;

   /* Get the EA data. */
   cr = info.flFlags & CFF_EXTEAS
      ? readExternalEAs(pVolume, info.idEAFile,
         &info2, info.cbEAs, pabEAs)
      : readInternalEAs(pVolume, id, info.cbEAs, pabEAs);
   if (cr) {
      sysFreeSecureMem(pabEAs);
      return cr;
   }

   /* Decode the EA data. */
   cr = decodeEAs(info.cbEAs, pabEAs, ppEAs);
   sysFreeSecureMem(pabEAs);
   if (cr) return cr;

   return CORERC_OK;
}


static CoreResult encodeEAs(CryptedEA * pEAs, unsigned int * pcbEAs,
   octet * * ppabEAs)
{
   CryptedEA * pCur;
   unsigned int cbEAs = 1, cb;
   octet * pabEAs, * pabCur;

   if (!pEAs) {
      *pcbEAs = 0;
      *ppabEAs = sysAllocSecureMem(0);
      if (!*ppabEAs) return CORERC_NOT_ENOUGH_MEMORY;
      return CORERC_OK;
   }

   for (pCur = pEAs; pCur; pCur = pCur->pNext)
      cbEAs += 6 + strlen(pCur->pszName) + pCur->cbValue;
   *pcbEAs = cbEAs;

   /* Allocate the EA data. */
   pabEAs = sysAllocSecureMem(cbEAs);
   if (!pabEAs) return CORERC_NOT_ENOUGH_MEMORY;
   
   /* Encode the EAs. */
   pabCur = pabEAs;
   for (pCur = pEAs; pCur; pCur = pCur->pNext) {
      *pabCur++ = pCur->flFlags | CEF_NOT_EOL;
      cb = strlen(pCur->pszName) + 1;
      memcpy(pabCur, pCur->pszName, cb);
      pabCur += cb;
      int32ToBytes(pCur->cbValue, pabCur);
      pabCur += 4;
      memcpy(pabCur, pCur->pabValue, pCur->cbValue);
      pabCur += pCur->cbValue;
   }
   *pabCur = 0;

   *pcbEAs = cbEAs;
   *ppabEAs = pabEAs;

   return CORERC_OK;
}


static CoreResult writeExternalEAs(CryptedVolume * pVolume,
   CryptedFileID id, unsigned int cbEAs, octet * pabEAs)
{
   CoreResult cr;
   CryptedFileInfo info;
   CryptedFilePos cbWritten;

   /* Get file info. */
   cr = coreQueryFileInfo(pVolume, id, &info);
   if (cr) return cr;

   /* Verify that it is an EA file. */
   if (!CFF_ISEA(info.flFlags)) return CORERC_BAD_TYPE;

   /* Write the encoded EAs to the EA file. */
   cr = coreWriteToFile(pVolume, id, 0, cbEAs, pabEAs, &cbWritten);
   if (cr) return cr;

   /* Truncate the EA file. */
   cr = coreSetFileSize(pVolume, id, cbEAs);
   if (cr) return cr;
   
   return CORERC_OK;
}


static CoreResult writeInternalEAs(CryptedVolume * pVolume,
   CryptedFileID id, unsigned int cbEAs, octet * pabEAs)
{
   CoreResult cr;

   assert(cbEAs <= MAX_INTERNAL_EAS);

   /* Write the new encoded EA set. */
   cr = coreSetSectorData(pVolume, INFOSECTORFILE_ID,
      coreQueryInfoSectorNumber(pVolume, id),
      sizeof(CryptedFileInfoOnDisk) + FILEINFO_RESERVED, cbEAs,
      0, pabEAs);
   if (cr) return cr;
   
   return CORERC_OK;
}


static CoreResult storeEAs(CryptedVolume * pVolume,
   CryptedFileID id, unsigned int cbEAs, octet * pabEAs)
{
   CoreResult cr;
   CryptedFileInfo info, info2;
   
   /* Get file info. */
   cr = getInfoAndVerify(pVolume, id, &info);
   if (cr) return cr;

   if (cbEAs > MAX_INTERNAL_EAS) {

      /* Store the EAs externally. */

      /* If the file currently does not have external EAs, then create
         an EA file. */
      if (!(info.flFlags & CFF_EXTEAS)) {
         memset(&info2, 0, sizeof(info2));
         info2.flFlags = CFF_IFEA;
         info2.cRefs = 1;
         info2.cbFileSize = cbEAs;
         info2.idParent = id;
         /* Note that the uid/gid are always 0 for EA files. */
         cr = coreCreateBaseFile(pVolume, &info2, &info.idEAFile);
         if (cr) return cr;
         info.flFlags |= CFF_EXTEAS;
      }
      
      cr = writeExternalEAs(pVolume, info.idEAFile, cbEAs, pabEAs);
      
   } else {

      /* Store the EAs internally. */

      /* If the file currently has external EAs, then delete the EA
         file. */
      if (info.flFlags & CFF_EXTEAS) {
         cr = coreDestroyBaseFile(pVolume, info.idEAFile);
         if (cr) return cr;
         info.flFlags &= ~CFF_EXTEAS;
         info.idEAFile = 0;
      }
      
      cr = writeInternalEAs(pVolume, id, cbEAs, pabEAs);
   }

   if (cr) return cr;

   info.cbEAs = cbEAs;

   cr = coreSetFileInfo(pVolume, id, &info);
   if (cr) return cr;

   return CORERC_OK;
}


CoreResult coreSetEAs(CryptedVolume * pVolume,
   CryptedFileID id, CryptedEA * pEAs)
{
   CoreResult cr;
   octet * pabEAs;
   unsigned int cbEAs;
   
   /* Encode the EAs. */
   cr = encodeEAs(pEAs, &cbEAs, &pabEAs);
   if (cr) return cr;

   cr = storeEAs(pVolume, id, cbEAs, pabEAs);
   sysFreeSecureMem(pabEAs);
   return cr;
}
