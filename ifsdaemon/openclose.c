/* openclose.c -- Create, open and close files.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: openclose.c,v 1.7 2001/09/23 13:30:13 eelco Exp $

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
#include <sysdep.h>

#include "aefsdmn.h"


/* Finish opening the file by creating an OpenFileData structure and
   filling in the sffsi structure and the opencreate result fields. */
static APIRET finalizeOpen(struct opencreate * popencreate,
   VolData * pVolData, CryptedFileID idFile, CryptedFileID idDir,
   char * pszName, CryptedFileInfo * pInfo, bool fHidden,
   USHORT usAction)
{
   OpenFileData * pOpenFileData = (OpenFileData *) &popencreate->sffsd;
      
   pOpenFileData->idFile = idFile;
   pOpenFileData->idDir = idDir;
   
   popencreate->usAction = usAction;
   pVolData->cOpenFiles++;

   /* Fill in the sffsi structure. */
   coreToSffsi(fHidden, pInfo, &popencreate->sffsi);
   popencreate->sffsi.sfi_position = 0;
   if (hasNon83Name(pszName))
      popencreate->sffsi.sfi_DOSattr |= FILE_NON83;
   logsffsi(&popencreate->sffsi);
   
   return NO_ERROR;
}


/* Create a new file with the specified attributes.  Postcondition:
   the creation either succeeds completely or no file is created at
   all. */
static APIRET createFile(struct opencreate * popencreate,
   VolData * pVolData, CryptedFileID idDir, char * pszName,
   PFEALIST pfeas, USHORT usAction)
{
   CoreResult cr;
   APIRET rc;
   CryptedVolume * pVolume = pVolData->pVolume;
   CryptedFileID idFile;
   CryptedFileInfo info;

   /* Create a new regular file with the requested initial size. */
   memset(&info, 0, sizeof(info));
   info.flFlags = CFF_IFREG | 0600; /* rw for user */
   info.cRefs = 1;
   info.cbFileSize = popencreate->sffsi.sfi_size;
   info.timeWrite = info.timeAccess = info.timeCreation = curTime();
   extractDOSAttr(popencreate->fsAttr, &info);
   /* uid and gid are set to 0 */
   cr = coreCreateBaseFile(pVolume, &info, &idFile);
   if (cr) return coreResultToOS2(cr);

   /* Set the extended attributes. */
   if (popencreate->fHasEAs) {
      rc = addEAs(pVolume, idFile, pfeas);
      if (rc) {
         coreDeleteFile(pVolume, idFile);
         return rc;
      }
   }

   /* Add the file to the directory. */
   cr = coreAddEntryToDir(pVolume, idDir, pszName, idFile,
      popencreate->fsAttr & FILE_HIDDEN ? CDF_HIDDEN : 0);
   if (cr) {
      coreDeleteFile(pVolume, idFile);
      return coreResultToOS2(cr);
   }

   return finalizeOpen(popencreate, pVolData, idFile, idDir, pszName,
      &info, popencreate->fsAttr & FILE_HIDDEN, usAction);
}


APIRET fsOpenCreate(ServerData * pServerData,
   struct opencreate * popencreate) 
{
   CoreResult cr;
   APIRET rc;
   VolData * pVolData;
   CryptedVolume * pVolume;
   CHAR szName[CCHMAXPATH];
   CryptedFileID idDir;
   CryptedFileID idFile;
   CryptedFileInfo info;
   CryptedDirEntry * pDirEntry;
   bool fHidden;
   
   popencreate->fsGenFlag = 0;
   popencreate->oError = 0;
   
   GET_VOLUME(popencreate);
   pVolume = pVolData->pVolume;
   
   if (VERIFYFIXED(popencreate->szName) ||
       verifyPathName(popencreate->szName))
      return ERROR_INVALID_PARAMETER;
   
   logMsg(L_DBG,
      "FS_OPENCREATE, szName=%s, flOpenMode=%08lx, "
      "fsOpenFlag=%04hx, fsAttr=%04hx, fHasEAs=%hd",
      popencreate->szName, popencreate->flOpenMode,
      popencreate->fsOpenFlag, popencreate->fsAttr,
      popencreate->fHasEAs);
   logsffsi(&popencreate->sffsi);

   /* We don't want DASD opens. */
   if (popencreate->flOpenMode & OPEN_FLAGS_DASD) {
      logMsg(L_WARN, "direct access open requested");
      return ERROR_NOT_SUPPORTED;
   }

   cr = findFromCurDir(pVolData, popencreate->szName, &popencreate->cdfsi,
       &popencreate->cdfsd, popencreate->iCurDirEnd, &idDir, &idFile,
       &pDirEntry, szName);
   if (!idDir) return coreResultToOS2(cr);

   switch (cr) {

      case CORERC_OK: /* file exists */

         /* Sanity check. */
         if (strlen((char *) pDirEntry->pabName) >= CCHMAXPATH) {
            coreFreeDirEntries(pDirEntry);
            return ERROR_ACCESS_DENIED;
         }

         fHidden = pDirEntry->flFlags & CDF_HIDDEN;
         coreFreeDirEntries(pDirEntry);

         /* Fail if exists? */
         if ((popencreate->fsOpenFlag & 0x000f) ==
            OPEN_ACTION_FAIL_IF_EXISTS)
            return ERROR_OPEN_FAILED;

         /* Get info. */
         cr = coreQueryFileInfo(pVolume, idFile, &info);
         if (cr) return coreResultToOS2(cr);

         /* It must be a regular file. */
         if (!CFF_ISREG(info.flFlags))
            return ERROR_ACCESS_DENIED;

         switch (popencreate->fsOpenFlag & 0x000f) {

            case OPEN_ACTION_OPEN_IF_EXISTS:

               if ((popencreate->flOpenMode & (OPEN_ACCESS_WRITEONLY |
                  OPEN_ACCESS_READWRITE)) &&
                  !(info.flFlags & CFF_IWUSR))
                  return ERROR_ACCESS_DENIED;

               return finalizeOpen(popencreate, pVolData, idFile,
                  idDir, szName, &info, fHidden, FILE_EXISTED);

            case OPEN_ACTION_REPLACE_IF_EXISTS:

               /* Delete the existing file. */
               rc = deleteFile(pVolData, popencreate->szName);
               if (rc) return rc;

               /* Create a new one. */
               return createFile(popencreate, pVolData, idDir, szName,
                  (PFEALIST) pServerData->pData, FILE_TRUNCATED);

            default:
               return ERROR_NOT_SUPPORTED;
         }
         
      case CORERC_FILE_NOT_FOUND: /* file does not exist */

         /* Should we create it? */
         if (!(popencreate->fsOpenFlag & OPEN_ACTION_CREATE_IF_NEW))
            return ERROR_OPEN_FAILED;

         /* Yes.  Create it with the requested initial size. */
         return createFile(popencreate, pVolData, idDir, szName,
            (PFEALIST) pServerData->pData, FILE_CREATED);
         
      default: /* error reading directory */
         return coreResultToOS2(cr);
   }
   
}


/* Close a file.  Problem: what should we do in case of an error?
   (And: what does the kernel do in case of an error?)
   Should we flush the entire file? */
APIRET fsClose(ServerData * pServerData, struct close * pclose)
{
   OpenFileData * pOpenFileData = (OpenFileData *) &pclose->sffsd;
   VolData * pVolData;
   APIRET rc;
   
   GET_VOLUME(pclose);
   
   logMsg(L_DBG,
      "FS_CLOSE, usType=%hu, fsIOFlag=%04hx",
      pclose->usType, pclose->fsIOFlag);
   logsffsi(&pclose->sffsi);

   rc = stampFileAndFlush(pVolData, pOpenFileData->idFile,
      &pclose->sffsi, SFAF_FLUSHINFO);
   if (rc) return rc;
   
   if (pclose->usType == FS_CL_FORSYS) {
      pVolData->cOpenFiles--;
      logMsg(L_DBG, "file closed");
   }
   else
      logMsg(L_DBG, "file not closed (not final)");
   
   return NO_ERROR;
}
