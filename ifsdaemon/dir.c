/* dir.c -- Directory operations: chdir, mkdir, and rmdir.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: dir.c,v 1.8 2001/09/23 13:30:13 eelco Exp $

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

#include "aefsdmn.h"


static APIRET changeDir(ServerData * pServerData,
   struct chdir * pchdir)
{
   CoreResult cr;
   VolData * pVolData;
   CryptedVolume * pVolume;
   CryptedFileID idDir;
   CryptedFileInfo info;
   
   if (VERIFYFIXED(pchdir->szDir) ||
       verifyPathName(pchdir->szDir))
      return ERROR_INVALID_PARAMETER;
   
   GET_VOLUME(pchdir);
   pVolume = pVolData->pVolume;
   
   logMsg(L_DBG, "CD_EXPLICIT, newdir=%s", pchdir->szDir);

   cr = findFromCurDir2(pVolData, pchdir->szDir, &pchdir->cdfsi,
       &pchdir->cdfsd, pchdir->iCurDirEnd, &idDir, 0);
   if (cr) return coreResultToOS2(cr);

   /* Get info */
   cr = coreQueryFileInfo(pVolume, idDir, &info);
   if (cr) return coreResultToOS2(cr);

   /* Is this really a directory? */
   if (!CFF_ISDIR(info.flFlags))
      /* This error code is not entirely concise, but it's what OS/2
         wants to see. */
      return ERROR_PATH_NOT_FOUND;

   pchdir->cdfsd.data[0] = idDir;
   
   return NO_ERROR;
}


static APIRET verifyDir(ServerData * pServerData,
   struct chdir * pchdir)
{
   return NO_ERROR;
}


static APIRET freeDir(ServerData * pServerData,
   struct chdir * pchdir)
{
   return NO_ERROR;
}


APIRET fsChDir(ServerData * pServerData, struct chdir * pchdir)
{
   if (VERIFYFIXED(pchdir->cdfsi.cdi_curdir))
      return ERROR_INVALID_PARAMETER;
   
   logMsg(L_DBG, "FS_CHDIR, flag=%d, cdfsi.dir=%s, cdfsi.flags=%d",
      pchdir->fsFlag, pchdir->cdfsi.cdi_curdir,
      pchdir->cdfsi.cdi_flags);

   switch (pchdir->fsFlag) {

      case CD_EXPLICIT:
         return changeDir(pServerData, pchdir);
      
      case CD_VERIFY:
         return verifyDir(pServerData, pchdir);
      
      case CD_FREE:
         return freeDir(pServerData, pchdir);
      
      default:
         logMsg(L_EVIL, "unknown FS_CHDIR flag: %d", pchdir->fsFlag);
         return ERROR_NOT_SUPPORTED;
         
   }
}


APIRET fsMkDir(ServerData * pServerData, struct mkdir * pmkdir)
{
   CoreResult cr;
   APIRET rc;
   VolData * pVolData;
   CryptedVolume * pVolume;
   CHAR szName[CCHMAXPATH];
   CryptedFileID idDir, idFile, idNewDir;
   CryptedFileInfo info;
   
   pmkdir->oError = 0;
   
   if (VERIFYFIXED(pmkdir->szName) ||
       verifyPathName(pmkdir->szName))
      return ERROR_INVALID_PARAMETER;
   
   GET_VOLUME(pmkdir);
   pVolume = pVolData->pVolume;
   
   logMsg(L_DBG, "FS_MKDIR, szName=%s, fsFlags=%d",
      pmkdir->szName, pmkdir->fsFlags);

   cr = findFromCurDir(pVolData, pmkdir->szName, &pmkdir->cdfsi,
       &pmkdir->cdfsd, pmkdir->iCurDirEnd, &idDir, &idFile, 0,
       szName);
   if (!idDir) return coreResultToOS2(cr);

   if (cr == CORERC_OK) return ERROR_ACCESS_DENIED;
   if (cr != CORERC_FILE_NOT_FOUND) return coreResultToOS2(cr);

   /* No.  Create a new directory. */
   memset(&info, 0, sizeof(info));
   info.flFlags = CFF_IFDIR | 0700; /* rwx for user */
   info.cRefs = 1;
   info.cbFileSize = 0;
   info.timeWrite = info.timeAccess = info.timeCreation = curTime();
   info.idParent = idDir;
   /* uid and gid are set to 0 */
   cr = coreCreateBaseFile(pVolume, &info, &idNewDir);
   if (cr) return coreResultToOS2(cr);

   /* Set the extended attributes. */
   if (pmkdir->fHasEAs) {
      rc = addEAs(pVolume, idNewDir, (PFEALIST) pServerData->pData);
      if (rc) {
         coreDeleteFile(pVolume, idNewDir);
         return rc;
      }
   }

   /* Add the directory to the parent directory. */
   cr = coreAddEntryToDir(pVolume, idDir, szName, idNewDir, 0);
   if (cr) {
      coreDeleteFile(pVolume, idNewDir);
      return coreResultToOS2(cr);
   }
   
   return NO_ERROR;
}


APIRET fsRmDir(ServerData * pServerData, struct rmdir * prmdir)
{
   CoreResult cr;
   VolData * pVolData;
   CryptedVolume * pVolume;
   CHAR szName[CCHMAXPATH];
   CryptedFileID idDir;
   CryptedFileID idFile;
   CryptedDirEntry * pFirstEntry;
   
   if (VERIFYFIXED(prmdir->szName) ||
       verifyPathName(prmdir->szName))
      return ERROR_INVALID_PARAMETER;
   
   GET_VOLUME(prmdir);
   pVolume = pVolData->pVolume;
   
   logMsg(L_DBG, "FS_RMDIR, szName=%s", prmdir->szName);

   cr = findFromCurDir(pVolData, prmdir->szName, &prmdir->cdfsi,
       &prmdir->cdfsd, prmdir->iCurDirEnd, &idDir, &idFile, 0,
       szName);
   if (cr) return coreResultToOS2(cr);

   /* Yes.  Read the directory contents.  (This implicitly makes sure
      that pFile is a directory. */
   cr = coreQueryDirEntries(pVolume, idFile, &pFirstEntry);
   if (cr || pFirstEntry) {
      coreFreeDirEntries(pFirstEntry);
      return cr ? coreResultToOS2(cr) : ERROR_CURRENT_DIRECTORY;
   }

   /* The directory is empty, so we can proceed with the deletion. */

   /* Remove the directory from its parent directory. */
   cr = coreMoveDirEntry(pVolume, szName, idDir, 0, 0);
   if (cr) return coreResultToOS2(cr);

   /* Delete the directory. */
   cr = coreDeleteFile(pVolume, idFile);
   if (cr) return coreResultToOS2(cr);
   
   return NO_ERROR;
}
