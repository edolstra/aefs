/* attach.h -- Handles (at|de)tachments and other volume stuff.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: attach.c,v 1.8 2001/09/23 13:30:13 eelco Exp $

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
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <io.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "aefsdmn.h"

#include "sysdep.h"
#include "ciphertable.h"
#include "superblock.h"


APIRET fsFsCtl(ServerData * pServerData, struct fsctl * pfsctl)
{
   int argc, ok, i;
   AEFS_SETPARAMS * params;
   char * p;
   char * * argv;
   
   APIRET error;
   
   logMsg(L_DBG,
      "FS_FSCTL, iArgType=%hd, usFunc=%hd, cbParm=%d, cbMaxData=%d",
      pfsctl->iArgType, pfsctl->usFunc, pfsctl->cbParm,
      pfsctl->cbMaxData);

   switch (pfsctl->usFunc) {

      case FSCTL_ERROR_INFO: /* return error info */
         if (pfsctl->cbParm < sizeof(USHORT))
            return ERROR_INVALID_PARAMETER;
         error = * (USHORT *) pServerData->pData;

         sprintf((char *) pServerData->pData, "AEFS error %ld",
            error);
         pfsctl->cbData = strlen((char *) pServerData->pData) + 1;
         if (pfsctl->cbData > pfsctl->cbMaxData)
            return ERROR_BUFFER_OVERFLOW;

         return NO_ERROR;

      case FSCTL_MAX_EASIZE: /* return max EA sizes */
         pfsctl->cbData = sizeof(EASIZEBUF);
         if (pfsctl->cbMaxData < sizeof(EASIZEBUF))
            return ERROR_BUFFER_OVERFLOW;

         ((PEASIZEBUF) pServerData->pData)->cbMaxEASize = 65535;
/*          ((PEASIZEBUF) pServerData->pData)->cbMaxEAListSize = 1 << 30; */
         ((PEASIZEBUF) pServerData->pData)->cbMaxEAListSize = 65535;

         return NO_ERROR;

      case FSCTL_AEFS_SETPARAMS: /* set daemon parameters */
         if (pfsctl->cbParm != sizeof(AEFS_SETPARAMS))
            return ERROR_INVALID_PARAMETER;

         params = (AEFS_SETPARAMS *) pServerData->pData;

         argc = 1;
         ok = 0;
         for (p = params->szParams;
              p < params->szParams + sizeof(params->szParams) - 1;
              p++)
            if (!*p) {
               argc++;
               if (!p[1]) {
                  ok = 1;
                  break;
               }
            }
         if (!ok) return ERROR_INVALID_PARAMETER;

         argv = alloca(argc * sizeof(char *));
         argv[0] = "fsctl";

         for (i = 1, p = params->szParams; i < argc; i++) {
            argv[i] = p;
            while (*p++) ;
         }
         
         return processArgs(pServerData, argc, argv, 0) ?
            ERROR_AEFS_SETAEFSPARAMS : NO_ERROR;

      default:
         return ERROR_NOT_SUPPORTED;
   }
}


static void dirtyCallBack(CryptedVolume * pVolume, bool fDirty)
{
   CoreResult cr;
   VolData * pVolData = (VolData *)
      coreQueryVolumeParms(pVolume)->pUserData;
   
   if (fDirty) { /* the volume now has dirty sectors */

      assert(!pVolData->fReadOnly);

      if (!(pVolData->pSuperBlock->flFlags & SBF_DIRTY)) {
         pVolData->pSuperBlock->flFlags |= SBF_DIRTY;
         cr = coreWriteSuperBlock(pVolData->pSuperBlock,
            CWS_NOWRITE_SUPERBLOCK1);
         if (cr)
            logMsg(L_ERR, "error setting dirty flag, cr=%d", cr);
      }
      
   } else { /* the volume now has no dirty sectors */
      /* Do nothing.  The superblock's dirty flag is periodically
         cleared by the lazy writer. */
   }
   
}


static APIRET attachVolume(ServerData * pServerData,
   struct attach * pattach)
{
   CoreResult cr;
   VolData * pVolData;
   AEFS_ATTACH * parms = (AEFS_ATTACH *) pServerData->pData;
   bool fReadOnly;
   CryptedVolumeParms vparms;
   char szFileName[MAX_VOLUME_BASE_PATH_NAME + 128];
   struct stat st;

   pattach->vpfsd.data[0] = (ULONG) -1;
   
   if ((pattach->cbParm != sizeof(AEFS_ATTACH)) ||
       VERIFYFIXED(parms->szBasePath) ||
       VERIFYFIXED(parms->szKey))
      return ERROR_INVALID_PARAMETER;
            
   logMsg(L_DBG, "attaching drive, basepath=%s", parms->szBasePath);

   /* The base path must be absolute. */
   if ((strncmp(parms->szBasePath, "\\\\", 2) != 0) && /* UNC */
       (strncmp(parms->szBasePath, "////", 2) != 0) && /* UNC */
       ((strlen(parms->szBasePath) < 3) ||
        (!isalpha((unsigned char) parms->szBasePath[0])) ||
        (parms->szBasePath[1] != ':') ||
        ((parms->szBasePath[2] != '\\') &&
         (parms->szBasePath[2] != '/'))))
      return ERROR_INVALID_PARAMETER;

   /* Append a slash, if necessary. */
   if (!IS_PATH_SEPARATOR(parms->szBasePath[
      strlen(parms->szBasePath) - 1]))
   {
      if (strlen(parms->szBasePath) == sizeof(parms->szBasePath) - 1)
         return ERROR_INVALID_PARAMETER;
      strcat(parms->szBasePath, "/");
   }

   /* Mount read-only?  Always do this if the user asks for it;
      otherwise check whether the superblock is writable. */
   
   fReadOnly = parms->flFlags & AP_READONLY;

   if (!fReadOnly) {

      if (snprintf(szFileName, sizeof(szFileName), "%s" SUPERBLOCK2_NAME,
         parms->szBasePath) >= sizeof(szFileName))
         return CORERC_INVALID_PARAMETER;

      if ((stat(szFileName, &st) == 0) &&
          (!(st.st_mode & S_IWUSR)))
      {
         logMsg(L_WARN, "cannot mount volume read/writeable, "
            "will mount read-only instead");
         fReadOnly = TRUE;
      }
   }

   /* Allocate a VolData structure. */
   pVolData = malloc(sizeof(VolData));
   if (!pVolData) {
      logMsg(L_EVIL, "out of memory");
      return ERROR_NOT_ENOUGH_MEMORY;
   }

   pVolData->pServerData = pServerData;
   pVolData->chDrive = toupper(pattach->szDev[0]);
   pVolData->fReadOnly = fReadOnly;
   pVolData->cOpenFiles = 0;
   pVolData->cSearches = 0;

   /* Open the volume. */
   coreSetDefVolumeParms(&vparms);
   vparms.fReadOnly = fReadOnly;
   vparms.cMaxCryptedFiles = pServerData->cMaxCryptedFiles;
   vparms.cMaxOpenStorageFiles = pServerData->cMaxOpenStorageFiles;
   vparms.csMaxCached = pServerData->csMaxCached;
   vparms.csIOGranularity = 512;
   if (vparms.csIOGranularity > vparms.csMaxCached)
      vparms.csIOGranularity = vparms.csMaxCached;
   vparms.dirtyCallBack = dirtyCallBack;
   vparms.pUserData = pVolData;

   cr = coreReadSuperBlock(parms->szBasePath, parms->szKey,
      cipherTable, &vparms, &pVolData->pSuperBlock);
   
   if (cr) {
      if (pVolData->pSuperBlock)
         coreDropSuperBlock(pVolData->pSuperBlock);
      logMsg(L_ERR, "unable to open volume, cr=%d", cr);
      free(pVolData);
      if (cr == CORERC_BAD_CHECKSUM)
         /* An encryption error almost certainly means an incorrect
            key. */
         return ERROR_INVALID_PASSWORD;
      else
         return coreResultToOS2(cr);
   }

   /* Is the volume dirty? */
   if (pVolData->pSuperBlock->flFlags & SBF_DIRTY) {
      logMsg(L_WARN, "volume %s is dirty", parms->szBasePath);
      if (!(parms->flFlags & AP_MOUNTDIRTY)) {
         coreDropSuperBlock(pVolData->pSuperBlock);
         free(pVolData);
         return ERROR_AEFS_DIRTY;
      }
   }

   pVolData->pVolume = pVolData->pSuperBlock->pVolume;
   pVolData->idRoot = pVolData->pSuperBlock->idRoot;

   pattach->vpfsd.data[0] = pVolData->chDrive - 'A';
   pServerData->paVolumes[pVolData->chDrive - 'A'] = pVolData;

   return NO_ERROR;
}


/* Flush dirty data and clear the dirty flag in the superblock. */
APIRET commitVolume(VolData * pVolData)
{
   CoreResult cr;

   if (pVolData->fReadOnly) return NO_ERROR;

   /* Flush all dirty data. */
   cr = coreFlushVolume(pVolData->pVolume);
   if (cr) {
      logMsg(L_ERR, "error flushing volume, cr=%d", cr);
      return coreResultToOS2(cr);
   }

   /* This will force open storage files to be commited. */
   cr = coreShrinkOpenStorageFiles(pVolData->pVolume, 0);
   if (cr) {
      logMsg(L_ERR, "error closing storage files, cr=%d", cr);
      return coreResultToOS2(cr);
   }

   if (pVolData->pSuperBlock->flFlags & SBF_DIRTY) {
      pVolData->pSuperBlock->flFlags &= ~SBF_DIRTY;
      cr = coreWriteSuperBlock(pVolData->pSuperBlock,
         CWS_NOWRITE_SUPERBLOCK1);
      if (cr) {
         logMsg(L_ERR, "error clearing dirty flag, cr=%d", cr);
         pVolData->pSuperBlock->flFlags |= SBF_DIRTY; /* retry */
         return coreResultToOS2(cr);
      }
   }

   return NO_ERROR;
}


void dropVolume(ServerData * pServerData, VolData * pVolData)
{
   CoreResult cr;
   int i;
   
   /* Close the volume */
   if (cr = coreDropSuperBlock(pVolData->pSuperBlock))
      /* Ignore errors, there's nothing we can do about it. */
      logMsg(L_EVIL, "error closing volume, cr=%d", cr);

   i = pVolData->chDrive - 'A';
   assert(pServerData->paVolumes[i] == pVolData);
   pServerData->paVolumes[i] = 0;

   free(pVolData);
}


static APIRET detachVolume(ServerData * pServerData,
   struct attach * pattach)
{
   APIRET rc;
   VolData * pVolData;
   AEFS_DETACH * parms = (AEFS_DETACH *) pServerData->pData;
   static AEFS_DETACH defparms = { 0 };

   if (pattach->cbParm != sizeof(AEFS_DETACH)) parms = &defparms;

   logMsg(L_DBG, "detaching drive, flFlags=%lx", parms->flFlags);

   pVolData = pServerData->paVolumes[pattach->vpfsd.data[0]];
   if (!pVolData) {
       logMsg(L_EVIL,
           "drive is unknown (left over from previous server?)");
       return NO_ERROR;
   }

   /* Open files or searches? */
   if (pVolData->cOpenFiles) {
      logMsg(L_EVIL, "volume still has %d open files",
         pVolData->cOpenFiles);
      if (!(parms->flFlags & DP_FORCE)) return ERROR_DRIVE_LOCKED;
   }
   
   if (pVolData->cSearches) {
      logMsg(L_EVIL, "volume still has %d open searches",
         pVolData->cSearches);
      if (!(parms->flFlags & DP_FORCE)) return ERROR_DRIVE_LOCKED;
   }

   /* Flush volume to disk. */
   rc = commitVolume(pVolData);
   if (rc) {
      logMsg(L_EVIL, "error committing volume during detach, rc=%d", rc);
      if (!(parms->flFlags & DP_FORCE)) return rc;
   }

   dropVolume(pServerData, pVolData);
   
   return NO_ERROR;
}


static APIRET queryAttachmentInfo(ServerData * pServerData,
   struct attach * pattach)
{
   if (pattach->cbParm < 2) {
      logMsg(L_ERR, "FS_ATTACH buffer too small, %d bytes",
         pattach->cbParm);
      pattach->cbParm = 2;
      return ERROR_BUFFER_OVERFLOW;
   }

   pattach->cbParm = 2;

   * (PUSHORT) pServerData->pData = 0;

   return NO_ERROR;
}


APIRET fsAttach(ServerData * pServerData, struct attach * pattach)
{
   APIRET rc;
   
   logMsg(L_DBG, "FS_ATTACH, flag=%hd, szDev=%s, cbParm=%d",
      pattach->fsFlag, pattach->szDev, pattach->cbParm);

   if (VERIFYFIXED(pattach->szDev) ||
       (strlen(pattach->szDev) != 2) ||
       (pattach->szDev[1] != ':'))
      return ERROR_INVALID_PARAMETER;

   switch (pattach->fsFlag) {

      case FSA_ATTACH:
         rc = attachVolume(pServerData, pattach);
         memset(pServerData->pData, 0, sizeof(AEFS_ATTACH)); /* burn */
         return rc;
         
      case FSA_DETACH:
         return detachVolume(pServerData, pattach);

      case FSA_ATTACH_INFO:
         return queryAttachmentInfo(pServerData, pattach);

      default:
         logMsg(L_EVIL, "unknown FS_ATTACH flag: %d", pattach->fsFlag);
         return ERROR_NOT_SUPPORTED;
   }
}


typedef unsigned long long uint64;

 
static APIRET getSetAllocInfo(ServerData * pServerData,
   struct fsinfo * pfsinfo, VolData * pVolData)
{
   PFSALLOCATE pfsalloc;
   FSALLOCATE fsallocReal;
   APIRET rc;
   uint64 cbUnit, cbTotal, cbAvail;
   
   if (pfsinfo->fsFlag == INFO_RETRIEVE) {
      
      if (pfsinfo->cbData < sizeof(FSALLOCATE))
         return ERROR_BUFFER_OVERFLOW;
      pfsinfo->cbData = sizeof(FSALLOCATE);

      /* Query info about the underlying file system. */
      rc = DosQueryFSInfo(
         toupper(pVolData->pSuperBlock->pszBasePath[0]) - 64,
         FSIL_ALLOC,
         &fsallocReal,
         sizeof(fsallocReal));
      if (rc) {
         cbTotal = 1024 * 1024 * 1024;
         cbAvail = 512 * 1024 * 1024;
      } else {
         cbUnit = fsallocReal.cbSector * fsallocReal.cSectorUnit;
         cbTotal = cbUnit * fsallocReal.cUnit;
         cbAvail = cbUnit * fsallocReal.cUnitAvail;
      }
      
      pfsalloc = (PFSALLOCATE) pServerData->pData;
      pfsalloc->idFileSystem = 0;
      pfsalloc->cSectorUnit = 1;
      pfsalloc->cUnit = cbTotal / PAYLOAD_SIZE;
      pfsalloc->cUnitAvail = cbAvail / PAYLOAD_SIZE;
      pfsalloc->cbSector = PAYLOAD_SIZE;
      return NO_ERROR;
      
   } else {
      logMsg(L_EVIL, "cannot set FSALLOCATE");
      return ERROR_NOT_SUPPORTED;
   }
}


static APIRET getSetVolSer(ServerData * pServerData,
   struct fsinfo * pfsinfo, VolData * pVolData)
{
   PFSINFO pinfo;
   PVOLUMELABEL pvollabel;
   char * pszLabel = pVolData->pSuperBlock->szLabel;
   
   if (pfsinfo->fsFlag == INFO_RETRIEVE) {
      if (pfsinfo->cbData < sizeof(FSINFO))
         return ERROR_BUFFER_OVERFLOW;
      else {
         pfsinfo->cbData = sizeof(FSINFO);
         pinfo = (PFSINFO) pServerData->pData;
         * (PULONG) &pinfo->fdateCreation = 0;
         pinfo->vol.cch = sizeof(pszLabel);
         strcpy(pinfo->vol.szVolLabel, pszLabel);
         return NO_ERROR;
      }
   } else {
      pvollabel = (PVOLUMELABEL) pServerData->pData;
      if ((pfsinfo->cbData < sizeof(VOLUMELABEL)) ||
          (pvollabel->cch > 11))
         return ERROR_INVALID_PARAMETER;
      else {
         strcpy(pszLabel, pvollabel->szVolLabel);
         pszLabel[pvollabel->cch] = 0;
         logMsg(L_DBG, "new volume label: %s", pszLabel);
         return coreResultToOS2(coreWriteSuperBlock(
            pVolData->pSuperBlock, CWS_NOWRITE_SUPERBLOCK1));
      }
   }
}


APIRET fsFsInfo(ServerData * pServerData, struct fsinfo * pfsinfo)
{
   VolData * pVolData;
    
   GET_VOLUME(pfsinfo);

   logMsg(L_DBG, "FS_FSINFO, flag=%hd, usLevel=%hd",
      pfsinfo->fsFlag, pfsinfo->usLevel);

   switch (pfsinfo->usLevel) {

      case FSIL_ALLOC:
         return getSetAllocInfo(pServerData, pfsinfo, pVolData);

      case FSIL_VOLSER:
         return getSetVolSer(pServerData, pfsinfo, pVolData);

      default:
         logMsg(L_EVIL, "unknown FS_INFO flag: %d", pfsinfo->fsFlag);
         return ERROR_NOT_SUPPORTED;
         
   }
}


APIRET fsFlushBuf(ServerData * pServerData,
   struct flushbuf * pflushbuf)
{
   VolData * pVolData;
   
   GET_VOLUME(pflushbuf);
   
   logMsg(L_DBG, "FS_FLUSHBUF, flag=%hd");

   if (pflushbuf->fsFlag & FLUSH_DISCARD)
      logMsg(L_WARN, "cannot discard data");

   return coreResultToOS2(coreFlushVolume(pVolData->pVolume));
}


APIRET fsShutdown(ServerData * pServerData,
   struct shutdown * pshutdown)
{
#if 0
   APIRET rc;
   VolData * pVolData;

   DosBeep((1 + pshutdown->usType) * 1000, 1000);

   logMsg(L_DBG, "FS_SHUTDOWN, usType=%hd", pshutdown->usType);

   if (pshutdown->usType == SD_BEGIN) {

      for (pVolData = pServerData->pFirstVolume;
           pVolData;
           pVolData = pVolData->pNext)
      {
         rc = commitVolume(pVolData);
         if (rc) logMsg(L_EVIL,
            "error committing volume during shutdown, rc=%d", rc);
      }

   }
#endif

   return NO_ERROR;
}
