/* find.c -- Read directory contents with file info.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: find.c,v 1.6 2001/09/23 13:30:13 eelco Exp $

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

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "aefsdmn.h"


void freeSearchData(SearchData * pSearchData)
{
   coreFreeDirEntries(pSearchData->pFirstInDir);
   free(pSearchData);
}


/* Determine whether the name matches with the search specification
   according to OS/2's meta-character rules.  !!! Time complexity is
   probably exponential in the worst case. */
static BOOL nameMatches(char * pszExp, char * pszName)
{
   switch (*pszExp) {

      case 0:
         while (*pszName == '.') pszName++;
         return !*pszName;

      case '*':
         return
            (*pszName && nameMatches(pszExp, pszName + 1)) ||
            nameMatches(pszExp + 1, pszName);

      case '?':
         return
            (!*pszName) ||
            ((*pszName == '.') &&
               nameMatches(pszExp + 1, pszName)) ||
            ((*pszName != '.') &&
               nameMatches(pszExp + 1, pszName + 1));

      case '.':
         return
            ((!*pszName) &&
               nameMatches(pszExp + 1, pszName)) ||
            ((*pszName == '.') &&
               nameMatches(pszExp + 1, pszName + 1));

      default:
         return (tolower(*pszExp) == tolower(*pszName)) &&
            nameMatches(pszExp + 1, pszName + 1);
      
   }
}


/* Check whether the directory entry matches the search criteria. */
static BOOL entryMatches(SearchData * pSearchData,
   CryptedDirEntry * pEntry)
{
   if ((pEntry->flFlags & CDF_HIDDEN) &&
       !(pSearchData->flAttr & FILE_HIDDEN))
      return false;
   
   if (!(pEntry->flFlags & CDF_HIDDEN) &&
       (pSearchData->flAttr & (FILE_HIDDEN << 8)))
      return false;

   if (!(pSearchData->flAttr & FILE_NON83) &&
       hasNon83Name((char *) pEntry->pabName))
      return false;
   
   return nameMatches(pSearchData->szName, (char *) pEntry->pabName);
}


/* Check whether the file matches the search criteria.  Note: the
   kernel never passes in "may-have" bits for the read-only and
   archive attributes. */
static BOOL fileMatches(SearchData * pSearchData,
   CryptedFileInfo * pInfo)
{
   BOOL fDir = CFF_ISDIR(pInfo->flFlags);
   BOOL fSystem = pInfo->flFlags & CFF_OS2S;

   if (fDir && !(pSearchData->flAttr & FILE_DIRECTORY))
      return false;
   
   if (!fDir && (pSearchData->flAttr & (FILE_DIRECTORY << 8)))
      return false;

   if (fSystem && !(pSearchData->flAttr & FILE_SYSTEM))
      return false;
   
   if (!fSystem && (pSearchData->flAttr & (FILE_SYSTEM << 8)))
      return false;

   if ((pInfo->flFlags & CFF_IWUSR) &&
       (pSearchData->flAttr & (FILE_READONLY << 8)))
      return false;

   if (!(pInfo->flFlags & CFF_OS2A) &&
       (pSearchData->flAttr & (FILE_ARCHIVED << 8)))
      return false;

   return true;
}


static void advanceSearch(SearchData * pSearchData)
{
   pSearchData->pNext = pSearchData->pNext->pNext;
   pSearchData->iNext++;
}


static APIRET storeNextFileInfo(
   CryptedVolume * pVolume,
   SearchData * pSearchData,
   PGEALIST pgeas,
   char * * ppData,
   ULONG * pcbData,
   ULONG ulLevel,
   ULONG flFlags)
{
   APIRET rc;
   CoreResult cr;
   CryptedDirEntry * pEntry;
   CryptedFileInfo info;
   
   while ((pEntry = pSearchData->pNext)) {

      logMsg(L_DBG, "testing entry %ld, flags=%x, id=%08x, name=%s",
         pSearchData->iNext,
         pEntry->flFlags, pEntry->idFile, (char *) pEntry->pabName);

      /* OS/2 file info relevant to file matching is stored in the
         directory (file name and hidden flag) and in the file's info
         sector (read-only, system, and archive flags).  So we try to
         reject the file by first looking at pEntry (fast) and then at
         the corresponding file's info sector (slow).  The last step
         also gives us all the necessary file info. */

      /* Does the current directory entry match the search criteria? */
      if (entryMatches(pSearchData, pEntry)) {

         logMsg(L_DBG, "entry matched");

         /* We must read the file's info sector to see whether the
            other flags (directory, read-only, archived) match with
            the criteria, and to return info about the file.  If
            the storage file no longer exists, however, we silently
            skip this entry.  Such a condition can occur when the file
            was deleted after the directory contents had been read.
            (It can also indicate an inconsistency (directory
            referring to non-existing file) but this should be handled
            by chkdsk). */
         
         cr = coreQueryFileInfo(pVolume, pEntry->idFile, &info);
         if (!cr && fileMatches(pSearchData, &info)) {

            logMsg(L_DBG, "file matched");

            /* Store the file information in the buffer. */
            if (!(pSearchData->flAttr & FILE_NON83))
               strupr((char *) pEntry->pabName); /* !!! codepage */
            rc = storeFileInfo(
               pVolume, pEntry->idFile, pgeas,
               (char *) pEntry->pabName,
               pEntry->flFlags & CDF_HIDDEN,
               &info,
               ppData, pcbData,
               ulLevel, flFlags, pSearchData->iNext);
            if (rc) return rc;
            
            advanceSearch(pSearchData);
            
            return NO_ERROR;
         }
         
      }
      
      advanceSearch(pSearchData);

   }

   return ERROR_NO_MORE_FILES;
}


static APIRET storeDirContents(
   CryptedVolume * pVolume,
   SearchData * pSearchData,
   PGEALIST pgeas,
   char * pData,
   ULONG cbData,
   ULONG ulLevel,
   PUSHORT pcMatch,
   ULONG flFlags)
{
   int cAdded = 0;
   int cMatch = *pcMatch;
   APIRET rc;

   if (!cMatch)
      return ERROR_INVALID_PARAMETER;

   *pcMatch = 0;
   
   do {
      
      rc = storeNextFileInfo(
         pVolume, pSearchData, pgeas,
         &pData, &cbData,
         ulLevel, flFlags);
      if (rc) {
         if (cAdded &&
             ((rc == ERROR_BUFFER_OVERFLOW) ||
              (rc == ERROR_EAS_DIDNT_FIT) ||  
              (rc == ERROR_NO_MORE_FILES)))
            break;
         if (rc == ERROR_EAS_DIDNT_FIT) {
            /* In the case that the EAs for the first entry don't fit,
               advance anyway so that the next query will return the
               next entry. */ 
            advanceSearch(pSearchData);
            *pcMatch = 1;
         }
         return rc; 
      }

      cAdded++;
      
   } while (cAdded < cMatch);

   *pcMatch = cAdded;

   return NO_ERROR;
}


APIRET fsFindFirst(ServerData * pServerData, struct
   findfirst * pfindfirst)
{
   APIRET rc;
   CoreResult cr;
   VolData * pVolData;
   CryptedVolume * pVolume;
   CryptedFileID idDir;
   CHAR szDir[CCHMAXPATH];
   SearchData * pSearchData;
   CryptedFileInfo info;
   PGEALIST pgeas = 0;

   pfindfirst->fsfsd.data[0] = 0;
   
   if (VERIFYFIXED(pfindfirst->szName) ||
       verifyPathName(pfindfirst->szName))
      return ERROR_INVALID_PARAMETER;
   
   GET_VOLUME(pfindfirst);
   pVolume = pVolData->pVolume;
   
   logMsg(L_DBG, "FS_FINDFIRST, curdir=%s, name=%s, "
      "iCurDirEnd=%d, fsAttr=%04hx, cMatch=%d, "
      "usLevel=%d, fsFlags=%04hx, cbData=%d",
      pfindfirst->cdfsi.cdi_curdir,
      pfindfirst->szName,
      pfindfirst->iCurDirEnd,
      pfindfirst->fsAttr,
      pfindfirst->cMatch,
      pfindfirst->usLevel,
      pfindfirst->fsFlags,
      pfindfirst->cbData);

   if (pfindfirst->usLevel != FIL_STANDARD &&
       pfindfirst->usLevel != FIL_QUERYEASIZE &&
       pfindfirst->usLevel != FIL_QUERYEASFROMLIST) {
      logMsg(L_EVIL, "unknown FS_FINDFIRST info level: %d",
         pfindfirst->usLevel);
      return ERROR_NOT_SUPPORTED;
   }

   /* Allocate the SearchData structure. */
   pSearchData = malloc(sizeof(SearchData));
   if (!pSearchData)
      return ERROR_NOT_ENOUGH_MEMORY;
   pSearchData->pFirstInDir = 0;
   pSearchData->flAttr = pfindfirst->fsAttr;

   /* Split the search specification. */
   splitPath(pfindfirst->szName, szDir, pSearchData->szName);

   logMsg(L_DBG, "dir=%s, spec=%s", szDir, pSearchData->szName);

   if (!*pSearchData->szName) {
      freeSearchData(pSearchData);
      return ERROR_INVALID_PARAMETER;
   }

   cr = findFromCurDir2(pVolData, szDir, &pfindfirst->cdfsi,
       &pfindfirst->cdfsd, pfindfirst->iCurDirEnd, &idDir, 0);
   if (cr) {
      freeSearchData(pSearchData);
      return coreResultToOS2(cr);
   }

   /* Read the directory contents. */
   cr = coreQueryDirEntries(pVolume, idDir, &pSearchData->pFirstInDir);
   if (cr) {
      /* Fail even if coreReadDir() returned partial directory
         contents. */
      freeSearchData(pSearchData);
      return coreResultToOS2(cr);
   }

   /* Make dummy structures for "." and "..". */
   
   pSearchData->pNext = &pSearchData->dot;
   pSearchData->iNext = 0;

   pSearchData->dot.pabName = (octet *) ".";
   pSearchData->dot.idFile = idDir;
   pSearchData->dot.flFlags = 0; /* ??? */

   if (idDir == pVolData->idRoot)
      /* There is no parent directory. */
      pSearchData->dot.pNext = pSearchData->pFirstInDir;
   else {
      cr = coreQueryFileInfo(pVolume, idDir, &info);
      if (cr) {
         freeSearchData(pSearchData);
         return coreResultToOS2(cr);
      }
      pSearchData->dot.pNext = &pSearchData->dotDot;
      pSearchData->dotDot.pNext = pSearchData->pFirstInDir;
      pSearchData->dotDot.pabName = (octet *) "..";
      pSearchData->dotDot.idFile = info.idParent;
      pSearchData->dotDot.flFlags = 0; /* ??? */
   }

   /* The GEAs are stored in the exchange buffer which is
      about to be overwritten; so make a copy. */
   if (pfindfirst->usLevel == FIL_QUERYEASFROMLIST) {
      pgeas = alloca(((PGEALIST) pServerData->pData)->cbList);
      memcpy(pgeas, pServerData->pData,
         ((PGEALIST) pServerData->pData)->cbList);
   }

   /* Store up to the requested number of items. */
   rc = storeDirContents(
      pVolume,
      pSearchData,
      pgeas,
      (char *) pServerData->pData,
      pfindfirst->cbData,
      pfindfirst->usLevel,
      &pfindfirst->cMatch,
      pfindfirst->fsFlags);
   if (rc && (rc != ERROR_EAS_DIDNT_FIT)) {
      freeSearchData(pSearchData);
      return rc;
   }

   logMsg(L_DBG, "%d entries returned", pfindfirst->cMatch);

   pfindfirst->fsfsd.data[0] = (ULONG) pSearchData;

   pVolData->cSearches++;

   return rc;
}


/* FS_FINDNEXT is used by the 16-bit DosFindNext API. */
APIRET fsFindNext(ServerData * pServerData,
   struct findnext * pfindnext)
{
   APIRET rc;
   VolData * pVolData;
   CryptedVolume * pVolume;
   SearchData * pSearchData = (SearchData *) pfindnext->fsfsd.data[0];
   PGEALIST pgeas = 0;
   
   GET_VOLUME(pfindnext);
   pVolume = pVolData->pVolume;
   
   logMsg(L_DBG, "FS_FINDNEXT, cMatch=%d, "
      "usLevel=%d, fsFlags=%d, cbData=%d",
      pfindnext->cMatch,
      pfindnext->usLevel,
      pfindnext->fsFlags,
      pfindnext->cbData);

   /* The GEAs are stored in the exchange buffer which is
      about to be overwritten; so make a copy. */
   if (pfindnext->usLevel == FIL_QUERYEASFROMLIST) {
      pgeas = alloca(((PGEALIST) pServerData->pData)->cbList);
      memcpy(pgeas, pServerData->pData,
         ((PGEALIST) pServerData->pData)->cbList);
   }

   /* Store up to the requested number of items. */
   rc = storeDirContents(
      pVolume,
      pSearchData,
      pgeas,
      (char *) pServerData->pData,
      pfindnext->cbData,
      pfindnext->usLevel,
      &pfindnext->cMatch,
      pfindnext->fsFlags);
   if (rc) return rc;

   logMsg(L_DBG, "%d entries returned", pfindnext->cMatch);

   return NO_ERROR;
}


/* FS_FINDFROMNAME is used by the 32-bit DosFindNext API. */
APIRET fsFindFromName(ServerData * pServerData,
   struct findfromname * pfindfromname)
{
   APIRET rc;
   VolData * pVolData;
   CryptedVolume * pVolume;
   SearchData * pSearchData = (SearchData *) pfindfromname->fsfsd.data[0];
   PGEALIST pgeas = 0;

   if (VERIFYFIXED(pfindfromname->szName))
      return ERROR_INVALID_PARAMETER;
   
   GET_VOLUME(pfindfromname);
   pVolume = pVolData->pVolume;
   
   logMsg(L_DBG, "FS_FINDFROMNAME, cMatch=%d, "
      "usLevel=%d, fsFlags=%d, cbData=%d, "
      "ulPosition=%d, szName=%s",
      pfindfromname->cMatch,
      pfindfromname->usLevel,
      pfindfromname->fsFlags,
      pfindfromname->cbData,
      pfindfromname->ulPosition,
      pfindfromname->szName);

#if 0
   if (pSearchData->iNext != pfindfromname->ulPosition + 1) {
      /* Does the kernel actually give us ulPositions not equal to
         the previous pSearchData->iNext?  Apparently only when the
         previous item(s) did not match, but then they still won't
         match so we can skip them.  So this code is commented out. */
      logMsg(L_EVIL, "interesting ulPosition (%ld vs. %ld)",
         pfindfromname->ulPosition, pSearchData->iNext);
      pSearchData->pNext = &pSearchData->dot;
      pSearchData->iNext = 0;
      while (pSearchData->pNext && (pSearchData->iNext !=
         pfindfromname->ulPosition))
         advanceSearch(pSearchData);
      if (!pSearchData->pNext)
         return ERROR_INVALID_PARAMETER;
      advanceSearch(pSearchData);
   }
#endif   

   /* The GEAs are stored in the exchange buffer which is
      about to be overwritten; so make a copy. */
   if (pfindfromname->usLevel == FIL_QUERYEASFROMLIST) {
      pgeas = alloca(((PGEALIST) pServerData->pData)->cbList);
      memcpy(pgeas, pServerData->pData,
         ((PGEALIST) pServerData->pData)->cbList);
   }

   /* Store up to the requested number of items. */
   rc = storeDirContents(
      pVolume,
      pSearchData,
      pgeas,
      (char *) pServerData->pData,
      pfindfromname->cbData,
      pfindfromname->usLevel,
      &pfindfromname->cMatch,
      pfindfromname->fsFlags);
   if (rc) return rc;

   logMsg(L_DBG, "%d entries returned", pfindfromname->cMatch);

   return NO_ERROR;
}


APIRET fsFindClose(ServerData * pServerData,
   struct findclose * pfindclose)
{
   VolData * pVolData;
    
   GET_VOLUME(pfindclose);
   
   logMsg(L_DBG, "FS_FINDCLOSE");

   /* It is possible to receive FS_FINDCLOSE _after_ the volume that
      the search applies to has been detached!  So it is important
      that FS_ATTACH[detach] is not over-zealous in cleaning up search
      data. */

   freeSearchData((SearchData *) pfindclose->fsfsd.data[0]);

   pVolData->cSearches--;

   return NO_ERROR;
}
