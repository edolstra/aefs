/* coreutils.c -- System-independent FS helper code.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: coreutils.c,v 1.4 2001/09/23 13:30:11 eelco Exp $

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

#include "coreutils.h"


CoreResult coreQueryIDFromPath(CryptedVolume * pVolume,
   CryptedFileID idStartDir, char * pszPath, CryptedFileID * pid,
   CryptedDirEntry * * ppEntry)
{
   CoreResult cr;
   char * pszPos;
   CryptedFileID id;
   CryptedDirEntry * pEntries, * pEntry;
   CryptedDirEntry * pClone = 0;
   
   *pid = 0;
   if (ppEntry) *ppEntry = 0;

   /* !!! reminder: check ppEntry allocation */

   /* Note that the empty path ("") is a valid identifier for
      idStartDir. */

   id = idStartDir;

   if (ppEntry) {
      cr = coreAllocDirEntry(0, 0, id, 0, &pClone);
      if (cr) return cr;
   }
   
   while (1) {
      
      /* Skip the leading separators. */
      while (*pszPath && IS_PATH_SEPARATOR(*pszPath))
         pszPath++;

      if (!*pszPath) break; /* no more components. */

      if (pClone) coreFreeDirEntries(pClone);

      /* Advance to the next separator, or the end. */
      pszPos = pszPath;
      while (*pszPos && !IS_PATH_SEPARATOR(*pszPos))
         pszPos++;

      /* Read the contents of the parent directory. */
      cr = coreQueryDirEntries(pVolume, id, &pEntries);
      if (cr) {
         coreFreeDirEntries(pEntries);
         return cr;
      }

      /* Look for the current component. */
      for (pEntry = pEntries;
           pEntry;
           pEntry = pEntry->pNext)
         /* !!! compareFileNames */
         if ((strlen((char *) pEntry->pabName) == pszPos - pszPath) &&
             (strnicmp((char *) pEntry->pabName, pszPath,
                pszPos - pszPath) == 0)) 
            break;

      if (!pEntry) {
         coreFreeDirEntries(pEntries);
         return CORERC_FILE_NOT_FOUND;
      }

      if (ppEntry) {
         cr = coreAllocDirEntry(pEntry->cbName, pEntry->pabName,
            pEntry->idFile, pEntry->flFlags, &pClone);
         if (cr) {
            coreFreeDirEntries(pEntries);
            return CORERC_NOT_ENOUGH_MEMORY;
         }
      }

      id = pEntry->idFile;

      coreFreeDirEntries(pEntries);
      
      pszPath = pszPos;
   }

   *pid = id;

   if (ppEntry) *ppEntry = pClone;

   return CORERC_OK;
}


CoreResult coreDeleteFile(CryptedVolume * pVolume, CryptedFileID id)
{
   CoreResult cr, crfinal = CORERC_OK;
   CryptedFileInfo info;
   
   /* Get file info. */
   cr = coreQueryFileInfo(pVolume, id, &info);
   if (cr) return cr;

   /* Destroy the file's EA file. */
   if (!CFF_ISEA(info.flFlags) && (info.flFlags & CFF_EXTEAS))
      crfinal = coreDestroyBaseFile(pVolume, info.idEAFile);

   /* Destroy the file. */
   cr = coreDestroyBaseFile(pVolume, id);
   if (cr) return cr;

   return crfinal;
}


static CoreResult addToList(char * pszName, CryptedFileID idFile, 
   unsigned int flFlags, CryptedDirEntry * * ppEntries)
{
   CoreResult cr;
   CryptedDirEntry * * ppCur = ppEntries, * pCur = *ppEntries, * pNew;
   int c;

   /* Find the insertion point. */
   while (pCur) {
      c = stricmp((char *) pCur->pabName, pszName);
      if (c == 0) return CORERC_FILE_EXISTS;
      if (c > 0) break;
      ppCur = &pCur->pNext;
      pCur = *ppCur;
   }

   /* Create new entry, insert it in the list. */
   cr = coreAllocDirEntry(strlen(pszName), (octet *) pszName,
      idFile, flFlags, &pNew);
   if (cr) return cr;
   pNew->pNext = pCur;
   *ppCur = pNew;
   
   return CORERC_OK;
}


static CryptedDirEntry * removeFromList(char * pszName,
   CryptedDirEntry * * ppEntries)
{
   CryptedDirEntry * * ppCur = ppEntries, * pCur = *ppEntries;
   while (pCur) {
      if (stricmp((char *) pCur->pabName, pszName) == 0) {
         *ppCur = pCur->pNext;
         pCur->pNext = 0;
         return pCur;
      }
      ppCur = &pCur->pNext;
      pCur = *ppCur;
   }
   return 0;
}


CoreResult coreAddEntryToDir(CryptedVolume * pVolume, CryptedFileID id,
   char * pszName, CryptedFileID idFile, unsigned int flFlags)
{
   CoreResult cr;
   CryptedDirEntry * pEntries;
   
   /* Query the contents of the directory. */
   cr = coreQueryDirEntries(pVolume, id, &pEntries);
   if (cr) {
      coreFreeDirEntries(pEntries);
      return cr;
   }

   /* Add the entry to the list. */
   cr = addToList(pszName, idFile, flFlags, &pEntries);
   if (cr) {
      coreFreeDirEntries(pEntries);
      return cr;
   }

   /* Update the directory. */
   cr = coreSetDirEntries(pVolume, id, pEntries);
   coreFreeDirEntries(pEntries);
   if (cr) return cr;

   return CORERC_OK;
}


CoreResult coreMoveDirEntry(
   CryptedVolume * pVolume,
   char * pszSrcName,
   CryptedFileID idSrcDir,
   char * pszDstName,
   CryptedFileID idDstDir)
{
   CoreResult cr;
   CryptedDirEntry * pSrcEntries, * pEntry;
   CryptedFileID idFile;
   CryptedFileInfo info;

   /* Query the contents of the source directory. */
   cr = coreQueryDirEntries(pVolume, idSrcDir, &pSrcEntries);
   if (cr) {
      coreFreeDirEntries(pSrcEntries);
      return cr;
   }

   /* Remove the file from the source directory. */
   pEntry = removeFromList(pszSrcName, &pSrcEntries);
   if (!pEntry) {
      coreFreeDirEntries(pSrcEntries);
      return CORERC_FILE_NOT_FOUND;
   }

   if (idDstDir) {

      if (idSrcDir == idDstDir)
         /* Source is the same as the target (simple rename). */
         cr = addToList(pszDstName, pEntry->idFile, 
            pEntry->flFlags, &pSrcEntries);
      else
         /* Source and target differ. */
         cr = coreAddEntryToDir(pVolume, idDstDir,
            pszDstName, pEntry->idFile, pEntry->flFlags);
      
      if (cr) {
         coreFreeDirEntries(pSrcEntries);
         coreFreeDirEntries(pEntry);
         return cr;
      }
   }

   idFile = pEntry->idFile;
   coreFreeDirEntries(pEntry);
   
   /* Update the source directory. */
   cr = coreSetDirEntries(pVolume, idSrcDir, pSrcEntries);
   coreFreeDirEntries(pSrcEntries);
   if (cr) return cr;

   /* If the moved file is a directory, we have to update its parent
      field. */
   if ((idSrcDir != idDstDir) && idDstDir) {
      cr = coreQueryFileInfo(pVolume, idFile, &info);
      if (cr) return cr;
      if (CFF_ISDIR(info.flFlags)) {
          info.idParent = idDstDir;
          cr = coreSetFileInfo(pVolume, idFile, &info);
          if (cr) return cr;
      }
   }

   return CORERC_OK;
}

