/* fileop.c -- File operations (move and delete).
   Copyright (C) 1999 Eelco Dolstra (edolstra@students.cs.uu.nl).

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


APIRET deleteFile(VolData * pVolData, char * pszFullName)
{
   CoreResult cr;
   CryptedVolume * pVolume = pVolData->pVolume;
   CHAR szDir[CCHMAXPATH], szName[CCHMAXPATH];
   CryptedFileID idDir;
   CryptedFileID idFile;
   CryptedFileInfo info;
   
   /* Split the file name. */
   splitPath(pszFullName + 2, szDir, szName);

   /* Find the parent directory. */
   cr = coreQueryIDFromPath(pVolume, pVolData->idRoot, szDir, &idDir, 0);
   if (cr) return coreResultToOS2(cr);

   /* Does a file with the specified name appear in the parent
      directory? */
   cr = coreQueryIDFromPath(pVolume, idDir, szName, &idFile, 0);
   if (cr) return coreResultToOS2(cr);

   /* Yes.  Get file info. */
   cr = coreQueryFileInfo(pVolume, idFile, &info);
   if (cr) return coreResultToOS2(cr);
   
   /* Make sure that the file is not a directory and not read-only. */
   if (CFF_ISDIR(info.flFlags) || !(info.flFlags & CFF_IWUSR))
      return ERROR_ACCESS_DENIED;

   /* Remove the file from its parent directory. */
   if (pVolData->fReadOnly) return ERROR_WRITE_PROTECT;
   cr = coreMoveDirEntry(pVolume, szName, idDir, 0, 0, 0);
   if (cr) return coreResultToOS2(cr);

   /* Lower the file's reference count.  If it dropped to zero, delete
      the file. */
   info.cRefs--;
   if (!info.cRefs) {
      cr = coreDeleteFile(pVolume, idFile);
      if (cr) return coreResultToOS2(cr);
   } else {
      cr = coreSetFileInfo(pVolume, idFile, &info);
      if (cr) return coreResultToOS2(cr);
   }
   
   return NO_ERROR;
}


APIRET fsDelete(ServerData * pServerData, struct delete * pdelete)
{
   VolData * pVolData;
   
   GET_VOLUME(pdelete);
   
   if (VERIFYFIXED(pdelete->szName) ||
       verifyPathName(pdelete->szName))
      return ERROR_INVALID_PARAMETER;
   
   logMsg(L_DBG, "FS_DELETE, szName=%s", pdelete->szName);

   return deleteFile(pVolData, pdelete->szName);
}


static APIRET setParent(CryptedVolume * pVolume,
   CryptedFileID idFile, CryptedFileID idParent)
{
   CoreResult cr;
   CryptedFileInfo info;
   
   /* Get file info. */
   cr = coreQueryFileInfo(pVolume, idFile, &info);
   if (cr) return coreResultToOS2(cr);

   if (!CFF_ISDIR(info.flFlags)) return NO_ERROR;

   /* Change the parent field. */
   info.idParent = idParent;

   return coreResultToOS2(coreSetFileInfo(pVolume, idFile, &info));
}


APIRET fsMove(ServerData * pServerData, struct move * pmove)
{
   CoreResult cr;
   VolData * pVolData;
   CryptedVolume * pVolume;
   APIRET rc;
   CHAR szSrcDir[CCHMAXPATH], szSrcName[CCHMAXPATH];
   CryptedFileID idSrcDir;
   CHAR szDstDir[CCHMAXPATH], szDstName[CCHMAXPATH];
   CryptedFileID idDstDir;
   CryptedDirEntry * pEntry;
   
   if (VERIFYFIXED(pmove->szSrc) ||
       verifyPathName(pmove->szSrc) ||
       VERIFYFIXED(pmove->szDst) ||
       verifyPathName(pmove->szDst))
      return ERROR_INVALID_PARAMETER;
   
   GET_VOLUME(pmove);
   pVolume = pVolData->pVolume;
   
   logMsg(L_DBG, "FS_MOVE, szSrc=%s, szDst=%s",
      pmove->szSrc, pmove->szDst);

   /* Split the source and target file names. */
   splitPath(pmove->szSrc, szSrcDir, szSrcName);
   splitPath(pmove->szDst, szDstDir, szDstName);

   /* Find the source directory. */
   cr = findFromCurDir2(pVolData, szSrcDir, &pmove->cdfsi,
       &pmove->cdfsd, pmove->iSrcCurDirEnd, &idSrcDir, 0);
   if (cr) return coreResultToOS2(cr);

   /* Find the target directory. */
   cr = findFromCurDir2(pVolData, szDstDir, &pmove->cdfsi,
       &pmove->cdfsd, pmove->iDstCurDirEnd, &idDstDir, 0);
   if (cr) return coreResultToOS2(cr);
   
   /* Perform the move operation. */
   if (pVolData->fReadOnly) return ERROR_WRITE_PROTECT;
   cr = coreMoveDirEntry(pVolume, szSrcName,
      idSrcDir, szDstName, idDstDir, &pEntry);
   if (cr) return coreResultToOS2(cr);

   /* If the file we just moved was a directory, we must update its
      idParent field. */
   rc = setParent(pVolume, pEntry->idFile, idDstDir);
   coreFreeDirEntries(pEntry);
   return rc;
}
