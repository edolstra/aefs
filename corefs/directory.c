/* directory.c -- Directory access and modification.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id$

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

#include <assert.h>
#include <string.h>

#include "corefs.h"
#include "sysdep.h"


CoreResult coreAllocDirEntry(const octet * pszName,
   CryptedFileID idFile, unsigned int flFlags, 
   CryptedDirEntry * * ppEntry)
{
   int cbName = strlen((const char *) pszName);
   CryptedDirEntry * pEntry;

   pEntry = sysAllocSecureMem(sizeof(CryptedDirEntry) + cbName + 1);
   if (!pEntry) return CORERC_NOT_ENOUGH_MEMORY;

   pEntry->pNext = 0;
   pEntry->pszName = sizeof(CryptedDirEntry) + (char *) pEntry;
   pEntry->idFile = idFile;
   pEntry->flFlags = flFlags;
   strcpy(pEntry->pszName, pszName);

   *ppEntry = pEntry;

   return CORERC_OK;
}


void coreFreeDirEntries(CryptedDirEntry * pEntries)
{
   CryptedDirEntry * pNext;
   for ( ; pEntries; pEntries = pNext) {
      pNext = pEntries->pNext;
      sysFreeSecureMem(pEntries);
   }
}


static CoreResult decodeDir(CryptedFilePos cbDir,
   octet * pabDir, CryptedDirEntry * * ppEntries)
{
   CoreResult cr;
   unsigned int flFlags;
   unsigned int cbName;
   char * pszName, save;
   CryptedFileID idFile;
   
   while (cbDir && *pabDir) {
      
      flFlags = *pabDir & ~CDF_NOT_EOL;
      cbDir--, pabDir++;

      /* Get the file ID, the name length, and the name. */
      if (cbDir < 8) return CORERC_BAD_DIRECTORY;
      idFile = bytesToInt32(pabDir);
      cbName = bytesToInt32(pabDir + 4);
      cbDir -= 8, pabDir += 8;
      pszName = pabDir;
      if (cbDir < cbName) return CORERC_BAD_DIRECTORY;
      cbDir -= cbName, pabDir += cbName;
      
      /* Create a new directory entry structure. */
      save = pszName[cbName]; /* horrible hack */
      pszName[cbName] = 0;
      cr = coreAllocDirEntry(pszName, idFile, flFlags, ppEntries);
      pszName[cbName] = save;
      if (cr) return cr;
      ppEntries = &(*ppEntries)->pNext;
   }
   
   if (cbDir != 1) return CORERC_BAD_DIRECTORY;
      
   return CORERC_OK;
}


CoreResult coreQueryDirEntries(CryptedVolume * pVolume,
   CryptedFileID id, CryptedDirEntry * * ppEntries)
{
   CoreResult cr, crread;
   CryptedFileInfo info;
   CryptedFilePos cbRead;
   octet * pabBuffer;
   
   *ppEntries = 0;

   /* Get file info. */
   cr = coreQueryFileInfo(pVolume, id, &info);
   if (cr) return cr;

   if (!CFF_ISDIR(info.flFlags)) return CORERC_NOT_DIRECTORY;

   if (!info.cbFileSize) return CORERC_OK;
   
   /* Allocate memory for the encoded directory data. */
   /* Note: alloc extra byte for hack in decodeDir(). */
   pabBuffer = sysAllocSecureMem(info.cbFileSize + 1);
   if (!pabBuffer)
      return CORERC_NOT_ENOUGH_MEMORY;
   
   /* Read the directory.  Continue even if an error occurs, because
      part of the directory might still be readable. */
   crread = coreReadFromFile(pVolume, id, 0,
      info.cbFileSize, pabBuffer, &cbRead);

   /* Decode the directory data. */
   cr = decodeDir(cbRead, pabBuffer, ppEntries);
   sysFreeSecureMem(pabBuffer);
   return crread ? crread : cr;
}


CoreResult coreSetDirEntries(CryptedVolume * pVolume,
   CryptedFileID id, CryptedDirEntry * pEntries)
{
   CoreResult cr;
   CryptedFilePos cbDirSize;
   CryptedFilePos cbWritten;
   CryptedDirEntry * pEntry;
   octet * pabBuffer, * pabPos;
   unsigned int cbName;

   if (!pEntries) return coreSetFileSize(pVolume, id, 0);
   
   /* How big will the directory be? */
   cbDirSize = 1;
   for (pEntry = pEntries;
        pEntry;
        pEntry = pEntry->pNext)
      cbDirSize += 9 + strlen(pEntry->pszName);

   /* Allocate memory. */
   pabBuffer = sysAllocSecureMem(cbDirSize);
   if (!pabBuffer) return CORERC_NOT_ENOUGH_MEMORY;

   /* Build the directory contents. */
   pabPos = pabBuffer;
   for (pEntry = pEntries;
        pEntry;
        pEntry = pEntry->pNext)
   {
      cbName = strlen(pEntry->pszName);
      *pabPos = pEntry->flFlags | CDF_NOT_EOL;
      int32ToBytes(pEntry->idFile, pabPos + 1);
      int32ToBytes(cbName, pabPos + 5);
      memcpy(pabPos + 9, pEntry->pszName, cbName);
      pabPos += 9 + cbName;
   }

   *pabPos = 0;
   
   /* Write the directory contents. */
   cr = coreWriteToFile(pVolume, id, 0,
      cbDirSize, pabBuffer, &cbWritten);
   sysFreeSecureMem(pabBuffer);
   if (cr) return cr;
   assert(cbWritten == cbDirSize);
   
   /* Shrink the directory file to cbDirSize. */
   cr = coreSetFileSize(pVolume, id, cbDirSize);
   if (cr) return cr;

   return CORERC_OK;
}
