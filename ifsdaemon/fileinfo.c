/* fileinfo.c -- Set and query file information.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: fileinfo.c,v 1.8 2001/09/23 13:30:13 eelco Exp $

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

#include <alloca.h>

#include "aefsdmn.h"


APIRET storeFileInfo(
   CryptedVolume * pVolume, /* DosFindXXX level 3 only */
   CryptedFileID idFile, /* DosFindXXX level 3 only */
   PGEALIST pgeas, /* DosFindXXX level 3 only */
   char * pszFileName, /* DosFindXXX only */
   bool fHidden,
   CryptedFileInfo * pInfo,
   char * * ppData,
   ULONG * pcbData,
   ULONG ulLevel,
   ULONG flFlags,
   int iNext)
{
   APIRET rc, finalrc = NO_ERROR;
   PFILESTATUS pBuf;
   int c;

   /* This information allows the search to continue from a specific
      file (for FS_FINDFROMNAME). */
   if (flFlags & FF_GETPOS) {
      if (*pcbData < sizeof(ULONG))
         return ERROR_BUFFER_OVERFLOW;
      * (PULONG) *ppData = iNext;
      *ppData += sizeof(ULONG);
      *pcbData -= sizeof(ULONG);
   }

   /* Store the level 1 file info. */
   if (*pcbData < sizeof(FILESTATUS))
      return ERROR_BUFFER_OVERFLOW;
   pBuf = (PFILESTATUS) *ppData;
   coreTimeToOS2(pInfo->timeCreation,
      &pBuf->fdateCreation, &pBuf->ftimeCreation);
   coreTimeToOS2(pInfo->timeAccess,
      &pBuf->fdateLastAccess, &pBuf->ftimeLastAccess);
   coreTimeToOS2(pInfo->timeWrite,
      &pBuf->fdateLastWrite, &pBuf->ftimeLastWrite);
   if (CFF_ISDIR(pInfo->flFlags)) {
      pBuf->cbFile = 0;
      pBuf->cbFileAlloc = 0;
   } else {
      pBuf->cbFile = pInfo->cbFileSize;
      pBuf->cbFileAlloc = (pInfo->csSet + 1) * SECTOR_SIZE; 
   }
   pBuf->attrFile = makeDOSAttr(fHidden, pInfo);
   *ppData += sizeof(FILESTATUS);
   *pcbData -= sizeof(FILESTATUS);

   /* Store the requested or all EAs for FS_FINDXXX level 3 and
      FS_PATH/FILEINFO levels 3 and 4. */
   if (ulLevel == FIL_QUERYEASFROMLIST) {
      rc = storeEAsInFEAList(pVolume, idFile,
         pInfo, pgeas, *pcbData, *ppData);
      if (rc == ERROR_BUFFER_OVERFLOW) {
         /* If the EAs don't fit, try to store level 2 info.  If that
            works, return ERROR_EAS_DIDNT_FIT.  However, if that
            doesn't fit either, return ERROR_BUFFER_OVERFLOW (see
            below). */
         ulLevel = FIL_QUERYEASIZE;
         finalrc = ERROR_EAS_DIDNT_FIT;
      } else {
         if (rc) return rc;
         *pcbData -= ((PFEALIST) *ppData)->cbList;
         *ppData += ((PFEALIST) *ppData)->cbList;
      }
   }

   /* Store the size of the EA set on disk for level 2. */
   if (ulLevel == FIL_QUERYEASIZE) {
      if (*pcbData < sizeof(ULONG))
         return ERROR_BUFFER_OVERFLOW;
      * (PULONG) *ppData = pInfo->cbEAs ? pInfo->cbEAs + 2 : 0;
      *ppData += sizeof(ULONG);
      *pcbData -= sizeof(ULONG);
   }

   /* Store the file name, if one was given (for FS_FINDXXX). */
   if (pszFileName) {
      c = strlen(pszFileName);
      if (c > 255)
         return ERROR_FILENAME_EXCED_RANGE;
      if (*pcbData < c + 2)
         return ERROR_BUFFER_OVERFLOW;
      * (PUCHAR) *ppData = c;
      memcpy(*ppData + 1, pszFileName, c + 1);
      *ppData += c + 2;
      *pcbData -= c + 2;
   }
      
   return finalrc;
}


/* Update file time stamps if required.  Flush none, some or all of
   the file to disk. */
APIRET stampFileAndFlush(VolData * pVolData, CryptedFileID idFile,
   struct sffsi * psffsi, int flush)
{
   CoreResult cr;
   CryptedVolume * pVolume = pVolData->pVolume;
   CryptedFileInfo info;

   /* If any of the ST_Sxxx stamp bits is set, copy the sffsi times
      into the info sector. */
   if (!pVolData->fReadOnly &&
       ((psffsi->sfi_tstamp & (ST_SCREAT | ST_SWRITE)) ||
        ((psffsi->sfi_tstamp & ST_SREAD) &&
         !pVolData->pServerData->fLazyLastAccess)))
   {
      cr = coreQueryFileInfo(pVolume, idFile, &info);
      if (cr) return coreResultToOS2(cr);

      /* Copy the time stamps from the sffsi. */
      os2TimeToCore(
         * (FDATE *) &psffsi->sfi_cdate,
         * (FTIME *) &psffsi->sfi_ctime,
         &info.timeCreation);
      os2TimeToCore(
         * (FDATE *) &psffsi->sfi_adate,
         * (FTIME *) &psffsi->sfi_atime,
         &info.timeAccess);
      os2TimeToCore(
         * (FDATE *) &psffsi->sfi_mdate,
         * (FTIME *) &psffsi->sfi_mtime,
         &info.timeWrite);

      if (psffsi->sfi_tstamp & ST_SWRITE)
         info.flFlags |= CFF_OS2A;

      /* Write the info sector. */
      cr = coreSetFileInfo(pVolume, idFile, &info);
      if (cr) return coreResultToOS2(cr);
   }

   psffsi->sfi_tstamp = 0;

   switch (flush) {

      case SFAF_NOFLUSH:
         break;

      case SFAF_FLUSHINFO:
         /* Flush the info sector if it's in the cache and dirty. */
         cr = coreFlushSector(pVolume, INFOSECTORFILE_ID,
            coreQueryInfoSectorNumber(pVolume, idFile));
         if (cr) return coreResultToOS2(cr);
         break;
         
      case SFAF_FLUSHALL:
         if (cr = coreFlushFile(pVolume, idFile))
            return coreResultToOS2(cr);
         break;

      default:
         abort();
   }

   return NO_ERROR;
}



/* Set the archived bit and the last write time. */
APIRET easChanged(CryptedVolume * pVolume, CryptedFileID idFile,
   bool fHidden, struct sffsi * psffsi)
{
   CoreResult cr;
   CryptedFileInfo info;
   
   cr = coreQueryFileInfo(pVolume, idFile, &info);
   if (cr) return coreResultToOS2(cr);
   
   info.flFlags |= CFF_OS2A;
   info.timeWrite = curTime();

   if (psffsi) {
      psffsi->sfi_tstamp = (psffsi->sfi_tstamp | ST_PWRITE) &
         ~ST_SWRITE;
      coreToSffsi(fHidden, &info, psffsi);
   }

   return coreResultToOS2(coreSetFileInfo(pVolume, idFile, &info));
}


CoreResult setHiddenFlag(CryptedVolume * pVolume,
   CryptedFileID idDir, CryptedFileID idFile, bool fHidden)
{
   CoreResult cr;
   CryptedDirEntry * pEntries, * pCur;
   bool fFound = false;
   
   cr = coreQueryDirEntries(pVolume, idDir, &pEntries);
   if (cr) {
      coreFreeDirEntries(pEntries);
      return cr;
   }

   for (pCur = pEntries; pCur; pCur = pCur->pNext)
      if (pCur->idFile == idFile) {
         fFound = true;
         if (fHidden)
            pCur->flFlags |= CDF_HIDDEN;
         else
            pCur->flFlags &= ~CDF_HIDDEN;
      }

   if (!fFound) {
      coreFreeDirEntries(pEntries);
      return CORERC_FILE_NOT_FOUND;
   }

   cr = coreSetDirEntries(pVolume, idDir, pEntries);
   coreFreeDirEntries(pEntries);
   return cr;
}


/* Boolean equivalence test (i.e. bi-implication a <-> b). */
static __inline__ int beq(int a, int b)
{
   return (a && b) || (!a && !b);
}


APIRET doTimeChange(ULONG os2time, CoreTime * pcoretime,
   struct sffsi * psffsi, int stamp)
{
   if (os2time) {
      if (os2TimeToCore(
         * (FDATE *) &os2time,
         * (1 + (FTIME *) &os2time),
         pcoretime))
         return ERROR_INVALID_PARAMETER;
      if (psffsi) psffsi->sfi_tstamp = (psffsi->sfi_tstamp |
         (stamp << 1)) & ~stamp;
   }
   return NO_ERROR;
}


APIRET setLevel1Info(CryptedVolume * pVolume, struct sffsi * psffsi,
   CryptedFileID idFile, CryptedFileID idDir, bool fHidden,
   PFILESTATUS pStat)
{
   CoreResult cr;
   APIRET rc;
   CryptedFileInfo info;

   cr = coreQueryFileInfo(pVolume, idFile, &info);
   if (cr) return coreResultToOS2(cr);

   if (!beq(CFF_ISDIR(info.flFlags),
      pStat->attrFile & FILE_DIRECTORY))
      return ERROR_INVALID_PARAMETER;

   if (rc = doTimeChange(* (ULONG *) &pStat->fdateCreation,
      &info.timeCreation, psffsi, ST_SCREAT)) return rc;
   if (rc = doTimeChange(* (ULONG *) &pStat->fdateLastAccess,
      &info.timeAccess, psffsi, ST_SREAD)) return rc;
   if (rc = doTimeChange(* (ULONG *) &pStat->fdateLastWrite,
      &info.timeWrite, psffsi, ST_SWRITE)) return rc;
   
   extractDOSAttr(pStat->attrFile, &info);

   cr = coreSetFileInfo(pVolume, idFile, &info);
   if (cr) return coreResultToOS2(cr);

   if (!beq(fHidden, pStat->attrFile & FILE_HIDDEN)) {
      fHidden = pStat->attrFile & FILE_HIDDEN;
      cr = setHiddenFlag(pVolume, idDir, idFile, fHidden);
      if (cr) return coreResultToOS2(cr);
   }
   
   if (psffsi) coreToSffsi(fHidden, &info, psffsi);
   
   return NO_ERROR;
}


APIRET doFileInfo(struct sffsi * psffsi,
   ULONG flFlag, ULONG ulLevel,
   VolData * pVolData, CryptedFileID idFile,
   CryptedFileID idDir, bool fHidden,
   ULONG cbData, char * pData)
{
   CoreResult cr;
   APIRET rc;
   CryptedVolume * pVolume = pVolData->pVolume;
   CryptedFileInfo info;
   PGEALIST pgeas;
   
   /* Access the file and get file info. */
   cr = coreQueryFileInfo(pVolume, idFile, &info);
   if (cr) return coreResultToOS2(cr);

   if (flFlag & FI_SET) {

      /* Set file info. */

      switch (ulLevel) {

         case FIL_STANDARD: /* Set file info. */

            if (cbData < sizeof(FILESTATUS))
               return ERROR_INVALID_PARAMETER;
            return setLevel1Info(pVolume, psffsi, idFile, idDir,
               fHidden, (PFILESTATUS) pData);

         case FIL_QUERYEASIZE: /* Set EAs. */

            rc = addEAs(pVolume, idFile, (PFEALIST) pData);
            if (rc) return rc;
            return easChanged(pVolume, idFile, fHidden, psffsi);
            
         default:
            logMsg(L_EVIL,
               "unknown set-FS_[FILE|PATH]INFO info level: %d",
               ulLevel);
            return ERROR_NOT_SUPPORTED;
      }
      
   } else {

      /* Query file info. */

      switch (ulLevel) {

         case FIL_STANDARD:     
         case FIL_QUERYEASIZE: /* Query level 1 or 2 file info. */
            
            memset(pData, 0, cbData);
            return storeFileInfo(0, 0, 0, 0,
               fHidden,
               &info,
               &pData,
               &cbData,
               ulLevel,
               0, 0);

         case FIL_QUERYEASFROMLIST: /* Query level 3 (EA) file info. */

            /* The GEAs are stored in the exchange buffer which is
               about to be overwritten; so make a copy. */
            pgeas = alloca(((PGEALIST) pData)->cbList);
            memcpy(pgeas, pData, ((PGEALIST) pData)->cbList);
            
            return storeEAsInFEAList(pVolume, idFile,
               &info, pgeas, 65536, pData);

         case 4: /* Store the entire EA set. */

            return storeEAsInFEAList(pVolume, idFile,
               &info, 0, 65536, pData);

         default:
            logMsg(L_EVIL,
               "unknown query-FS_[FILE|PATH]INFO info level: %d",
               ulLevel);
            return ERROR_NOT_SUPPORTED;
      }
   }
}


APIRET fsFileInfo(ServerData * pServerData,
   struct fileinfo * pfileinfo)
{
   VolData * pVolData;
   OpenFileData * pOpenFileData = (OpenFileData *) &pfileinfo->sffsd;

   GET_VOLUME(pfileinfo);
   
   logMsg(L_DBG,
      "FS_FILEINFO, usLevel=%hd, cbData=%hd, "
      "fsFlag=%04hx, fsIOFlag=%04hx",
      pfileinfo->usLevel, pfileinfo->cbData,
      pfileinfo->fsFlag, pfileinfo->fsIOFlag);
   logsffsi(&pfileinfo->sffsi);

   return doFileInfo(
      &pfileinfo->sffsi,
      pfileinfo->fsFlag,
      pfileinfo->usLevel,
      pVolData,
      pOpenFileData->idFile,
      pOpenFileData->idDir,
      pfileinfo->sffsi.sfi_DOSattr & FILE_HIDDEN,
      pfileinfo->cbData,
      (char *) pServerData->pData);
}


APIRET fsPathInfo(ServerData * pServerData,
   struct pathinfo * ppathinfo)
{
   CoreResult cr;
   VolData * pVolData;
   CryptedVolume * pVolume;
   CHAR szName[CCHMAXPATH];
   CryptedFileID idDir;
   CryptedFileID idFile;
   CryptedDirEntry * pDirEntry;
   bool fHidden;
   
   if (VERIFYFIXED(ppathinfo->szName) ||
       verifyPathName(ppathinfo->szName))
      return ERROR_INVALID_PARAMETER;
   
   GET_VOLUME(ppathinfo);
   pVolume = pVolData->pVolume;
   
   logMsg(L_DBG,
      "FS_PATHINFO, szName=%s, usLevel=%hd, "
      "cbData=%hd, fsFlag=%04hx",
      ppathinfo->szName, ppathinfo->usLevel,
      ppathinfo->cbData, ppathinfo->fsFlag);
   
   cr = findFromCurDir(pVolData, ppathinfo->szName, &ppathinfo->cdfsi,
       &ppathinfo->cdfsd, ppathinfo->iCurDirEnd, &idDir, &idFile,
       &pDirEntry, szName);
   if (cr) return coreResultToOS2(cr);

   fHidden = pDirEntry->flFlags & CDF_HIDDEN;
   coreFreeDirEntries(pDirEntry);

   return doFileInfo(
      0,
      ppathinfo->fsFlag,
      ppathinfo->usLevel,
      pVolData,
      idFile,
      idDir,
      fHidden,
      ppathinfo->cbData,
      (char *) pServerData->pData);
}


APIRET fsFileAttribute(ServerData * pServerData,
   struct fileattribute * pfileattribute)
{
   CoreResult cr;
   VolData * pVolData;
   CryptedVolume * pVolume;
   CHAR szName[CCHMAXPATH];
   CryptedFileID idDir;
   CryptedFileID idFile;
   CryptedFileInfo info, info2;
   CryptedDirEntry * pDirEntry;
   bool fHidden;
   
   if (VERIFYFIXED(pfileattribute->szName) ||
       verifyPathName(pfileattribute->szName))
      return ERROR_INVALID_PARAMETER;
   
   GET_VOLUME(pfileattribute);
   pVolume = pVolData->pVolume;
   
   logMsg(L_DBG,
      "FS_FILEATTRIBUTE, szName=%s, fsFlag=%hd, fsAttr=%hd",
      pfileattribute->szName, pfileattribute->fsFlag,
      pfileattribute->fsAttr);
   
   cr = findFromCurDir(pVolData, pfileattribute->szName,
       &pfileattribute->cdfsi, &pfileattribute->cdfsd,
       pfileattribute->iCurDirEnd, &idDir, &idFile, &pDirEntry,
       szName);
   if (cr) return coreResultToOS2(cr);

   fHidden = pDirEntry->flFlags & CDF_HIDDEN;
   coreFreeDirEntries(pDirEntry);
   
   /* Access the file and get file info. */
   cr = coreQueryFileInfo(pVolume, idFile, &info);
   if (cr) return coreResultToOS2(cr);

   if (pfileattribute->fsFlag & FA_SET) {
      
      /* Set the file attributes. */
      
      /* Update the hidden flag in the directory, if necessary. */
      if (!beq(fHidden, pfileattribute->fsAttr & FILE_HIDDEN)) {
         cr = setHiddenFlag(pVolume, idDir, idFile,
            pfileattribute->fsAttr & FILE_HIDDEN);
         if (cr) return coreResultToOS2(cr);
      }

      /* Update the flags in the info sector, if necessary. */
      info2 = info;
      extractDOSAttr(pfileattribute->fsAttr, &info2);

      if (info2.flFlags != info.flFlags) {
         cr = coreSetFileInfo(pVolume, idFile, &info2);
         if (cr) return coreResultToOS2(cr);
      }

      return NO_ERROR;
      
   } else {
      /* Query the file attributes. */
      pfileattribute->fsAttr = makeDOSAttr(fHidden, &info);
      return NO_ERROR;
   }
}
