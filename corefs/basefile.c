/* basefile.c -- File I/O.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: basefile.c,v 1.8 2001/09/23 13:30:10 eelco Exp $

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

#include "corefs.h"


static SectorNumber fileSizeToAllocation(CryptedFilePos cbFileSize)
{
   return cbFileSize ? (cbFileSize - 1) / PAYLOAD_SIZE + 1 : 0;
}


/* Create a new file with the specified initial file size.
   Postcondition: this function either completes succesfully and
   completely creates and initializes a new file, or it fails
   totally (i.e. no partially initialized files are returned).
   Thus, *ppFile is not null iff the result is CORERC_OK. */
CoreResult coreCreateBaseFile(CryptedVolume * pVolume,
   CryptedFileInfo * pInfo, CryptedFileID * pid)
{
   CoreResult cr;
   SectorNumber cSectors;
   CryptedFileID id;

   *pid = 0;

   /* How many data sectors do we need for a file of cbInitialSize
      bytes? */
   cSectors = fileSizeToAllocation(pInfo->cbFileSize);

   /* Allocate an info sector, which gives us a new file ID. */
   cr = coreAllocID(pVolume, &id);
   if (cr) return cr;

   /* Create the storage file. */
   cr = coreCreateFile(pVolume, id, cSectors);
   if (cr) {
      coreFreeID(pVolume, id);
      return cr;
   }

   /* Initialize the info sector. */
   pInfo->csSet = 0;
   pInfo->cbEAs = 0;
   pInfo->idEAFile = 0;

   cr = coreSetFileInfo(pVolume, id, pInfo);
   if (cr) {
      coreDestroyBaseFile(pVolume, id);
      return cr;
   }

   *pid = id;
   
   return CORERC_OK;
}


CoreResult coreDestroyBaseFile(CryptedVolume * pVolume,
   CryptedFileID id)
{
   CoreResult cr;
   
   if (!id) return CORERC_INVALID_PARAMETER;
   
   cr = coreDestroyFile(pVolume, id);
   if (cr) return cr;

   cr = coreFreeID(pVolume, id);
   if (cr) return cr;

   return CORERC_OK;
}


CoreResult coreQueryFileInfo(CryptedVolume * pVolume,
   CryptedFileID id, CryptedFileInfo * pInfo)
{
   CoreResult cr;
   CryptedFileInfoOnDisk infoOnDisk;
   
   if (!id) return CORERC_INVALID_PARAMETER;
   
   /* Get the file's info sector. */
   cr = coreQuerySectorData(pVolume, INFOSECTORFILE_ID,
      coreQueryInfoSectorNumber(pVolume, id),
      0, sizeof(CryptedFileInfoOnDisk), 0, &infoOnDisk);
   if (cr) return cr;

   /* Copy the info in infoOnDisk to *pInfo. */
   pInfo->flFlags = bytesToInt32(infoOnDisk.flFlags);
   pInfo->cRefs = bytesToInt32(infoOnDisk.cRefs);
   pInfo->cbFileSize = bytesToInt32(infoOnDisk.cbFileSize);
   pInfo->csSet = bytesToInt32(infoOnDisk.csSet);
   pInfo->timeCreation = bytesToInt32(infoOnDisk.timeCreation);
   pInfo->timeAccess = bytesToInt32(infoOnDisk.timeAccess);
   pInfo->timeWrite = bytesToInt32(infoOnDisk.timeWrite);
   pInfo->idParent = bytesToInt32(infoOnDisk.idParent);
   pInfo->cbEAs = bytesToInt32(infoOnDisk.cbEAs);
   pInfo->idEAFile = bytesToInt32(infoOnDisk.idEAFile);
   pInfo->uid = bytesToInt32(infoOnDisk.uid);
   pInfo->gid = bytesToInt32(infoOnDisk.gid);

   /* Perform a few checks. */
   if ((bytesToInt32(infoOnDisk.magic) != INFOSECTOR_MAGIC_INUSE) ||
       (bytesToInt32(infoOnDisk.id) != id))
      return CORERC_BAD_INFOSECTOR;

   return CORERC_OK;
}


CoreResult coreSetFileInfo(CryptedVolume * pVolume,
   CryptedFileID id, CryptedFileInfo * pInfo)
{
   CoreResult cr;
   CryptedFileInfoOnDisk infoOnDisk;

   if (!id) return CORERC_INVALID_PARAMETER;

   memset(&infoOnDisk, 0, sizeof(infoOnDisk));
   
   /* Copy the info in *pInfo to infoOnDisk. */
   int32ToBytes(pInfo->flFlags, infoOnDisk.flFlags);
   int32ToBytes(pInfo->cRefs, infoOnDisk.cRefs);
   int32ToBytes(pInfo->cbFileSize, infoOnDisk.cbFileSize);
   int32ToBytes(pInfo->csSet, infoOnDisk.csSet);
   int32ToBytes(pInfo->timeCreation, infoOnDisk.timeCreation);
   int32ToBytes(pInfo->timeAccess, infoOnDisk.timeAccess);
   int32ToBytes(pInfo->timeWrite, infoOnDisk.timeWrite);
   int32ToBytes(pInfo->idParent, infoOnDisk.idParent);
   int32ToBytes(pInfo->cbEAs, infoOnDisk.cbEAs);
   int32ToBytes(pInfo->idEAFile, infoOnDisk.idEAFile);

   /* Set other stuff. */
   int32ToBytes(INFOSECTOR_MAGIC_INUSE, infoOnDisk.magic);
   int32ToBytes(id, infoOnDisk.id);
   int32ToBytes(pInfo->uid, infoOnDisk.uid);
   int32ToBytes(pInfo->gid, infoOnDisk.gid);

   /* Rewrite the file's info sector. */
   cr = coreSetSectorData(pVolume, INFOSECTORFILE_ID,
      coreQueryInfoSectorNumber(pVolume, id),
      0, sizeof(CryptedFileInfoOnDisk), 0, &infoOnDisk);
   if (cr) return cr;

   return CORERC_OK;
}


/* Read bytes from a file until the end-of-file is reached.  Reaching
   or starting beyond EOF is not an error.  The number of bytes read
   is returned in *pcbRead. */
CoreResult coreReadFromFile(CryptedVolume * pVolume, CryptedFileID id,
   CryptedFilePos fpStart, CryptedFilePos cbLength, octet * pabBuffer,
   CryptedFilePos * pcbRead)
{
   CoreResult cr;
   CryptedFileInfo info;
   SectorNumber csExtent;
   SectorNumber sCurrent;
   unsigned int offset, read;
   CryptedVolumeParms * pParms = coreQueryVolumeParms(pVolume);
   
   *pcbRead = 0;
   
   if (!id) return CORERC_INVALID_PARAMETER;
   
   if ((cr = coreQueryFileInfo(pVolume, id, &info))) return cr;

   /* Read starts beyond end of file?  Then we're done. */
   if (fpStart >= info.cbFileSize) return CORERC_OK;

   /* Read extends beyond end of file? */
   if (fpStart + cbLength > info.cbFileSize)
      cbLength = info.cbFileSize - fpStart;

   sCurrent = fpStart / PAYLOAD_SIZE;
   offset = fpStart % PAYLOAD_SIZE;

   /* Read the data. */
   while (cbLength && (sCurrent < info.csSet)) {

      /* Fetch at most csIOGranularity sectors. */
      csExtent = (offset + cbLength - 1) / PAYLOAD_SIZE + 1;
      if (sCurrent + csExtent > info.csSet)
         csExtent = info.csSet - sCurrent;
      if (csExtent > pParms->csIOGranularity)
         csExtent = pParms->csIOGranularity;
      cr = coreFetchSectors(pVolume, id, sCurrent, csExtent, 0);
      if (cr) return cr;

      /* Copy the sectors we just fetched into the buffer. */
      while (csExtent--) {
         read = PAYLOAD_SIZE - offset;
         if (read > cbLength) read = cbLength;

         cr = coreQuerySectorData(pVolume, id, sCurrent,
            offset, read, 0, pabBuffer);
         if (cr) return cr; /* shouldn't happen */
      
         pabBuffer += read;
         *pcbRead += read;
         cbLength -= read;
         sCurrent++;
         offset = 0;
      }
   }

   if (cbLength) {
      memset(pabBuffer, 0, cbLength);
      *pcbRead += cbLength;
   }

   return CORERC_OK;
}


static CoreResult zeroSectors(CryptedVolume * pVolume,
   CryptedFileID id, CryptedVolumeParms * pParms,
   CryptedFileInfo * pInfo, SectorNumber csInit)
{
   CoreResult cr;
   SectorNumber csExtent;
   
   while (pInfo->csSet < csInit) {
      csExtent = csInit - pInfo->csSet;
      if (csExtent > pParms->csIOGranularity)
         csExtent = pParms->csIOGranularity;
      cr = coreFetchSectors(pVolume, id, pInfo->csSet,
         csExtent, CFETCH_NO_READ); /* dirty and zero-filled */
      if (cr) return cr;
      pInfo->csSet += csExtent;
   }

   return CORERC_OK;
}


/* Write bytes to a file.  Zero-byte writes are not an error.  The
   number of bytes succesfully written is stored in *pcbWritten, which
   may be less than the given number of bytes iff an error occurs. */
CoreResult coreWriteToFile(CryptedVolume * pVolume, CryptedFileID id,
   CryptedFilePos fpStart, CryptedFilePos cbLength, octet * pabBuffer,
   CryptedFilePos * pcbWritten)
{
   CoreResult cr;
   CryptedFileInfo info;
   SectorNumber sCurrent;
   unsigned int offset, write;
   CryptedVolumeParms * pParms = coreQueryVolumeParms(pVolume);
   bool fChanged = false;
   SectorNumber csExtent;
   unsigned int flFlags;
   
   *pcbWritten = 0;
   
   if (!id) return CORERC_INVALID_PARAMETER;
   
   if ((cr = coreQueryFileInfo(pVolume, id, &info))) return cr;

   /* Ignore zero-length writes. */
   if (!cbLength) return CORERC_OK;

   /* Write (extends) beyond current end-of-file?  Then we allocate
      more storage sectors. */
   if (fpStart + cbLength > info.cbFileSize)
      if ((cr = coreSetFileSize(pVolume, id, fpStart + cbLength)) ||
          (cr = coreQueryFileInfo(pVolume, id, &info)))
         return cr;

   sCurrent = fpStart / PAYLOAD_SIZE;
   offset = fpStart % PAYLOAD_SIZE;

   /* Initialize uninitialized sectors lower than the start sector. */
   if (sCurrent > info.csSet) {
      cr = zeroSectors(pVolume, id, pParms, &info, sCurrent);
      if (cr) return cr;
      fChanged = true;
   }

   /* Write the data. */
   while (cbLength) {
      
      /* Make room in the cache for at most csIOGranularity sectors
         (and read from disk those sectors that are going to be
         partially overwritten). */

      flFlags = CFETCH_NO_READ;
      csExtent = (offset + cbLength - 1) / PAYLOAD_SIZE + 1;
      if ((sCurrent < info.csSet) &&
          (offset != 0 || cbLength < PAYLOAD_SIZE)) {
         if (offset + cbLength > PAYLOAD_SIZE &&
             offset + cbLength < 2 * PAYLOAD_SIZE &&
             sCurrent + 1 < info.csSet)
            csExtent = 2;
         else
            csExtent = 1;
         flFlags = 0;
      }
      if (csExtent > pParms->csIOGranularity)
         csExtent = pParms->csIOGranularity;

      cr = coreFetchSectors(pVolume, id, sCurrent, csExtent, flFlags);
      if (cr) {
         if (fChanged) 
            coreSetFileInfo(pVolume, id, &info); /* commit successful writes */
         return cr;
      }

      /* Copy buffer data into the sectors. */
      while (csExtent--) {
         write = PAYLOAD_SIZE - offset;
         if (write > cbLength) write = cbLength;
         
         cr = coreSetSectorData(pVolume, id, sCurrent,
            offset, write, flFlags, pabBuffer);
         if (cr) return cr; /* shouldn't happen */
         
         pabBuffer += write;
         *pcbWritten += write;
         cbLength -= write;
         sCurrent++;
         offset = 0;
      }

      if (sCurrent > info.csSet) {
         info.csSet = sCurrent;
         fChanged = true;
      }
   }

   if (fChanged)
      if ((cr = coreSetFileInfo(pVolume, id, &info))) return cr;

   return CORERC_OK;
}


/* Set the size of the file.  The number of sectors in the file is
   increased or decreased as required. */ 
CoreResult coreSetFileSize(CryptedVolume * pVolume, CryptedFileID id,
   CryptedFilePos cbFileSize)
{
   CoreResult cr;
   CryptedFileInfo info;
   SectorNumber cSectors;
   octet zero[PAYLOAD_SIZE];
   CryptedFilePos cbOldSize;
   unsigned int offset;
   
   if (!id) return CORERC_INVALID_PARAMETER;
   
   /* Get file info. */
   cr = coreQueryFileInfo(pVolume, id, &info);
   if (cr) return cr;
   cbOldSize = info.cbFileSize;

   if (info.cbFileSize == cbFileSize) return CORERC_OK;

   /* Change the file size. */
   info.cbFileSize = cbFileSize;

   /* How many sectors do we need? */
   cSectors = fileSizeToAllocation(cbFileSize);

   /* If the file shrinks, we might have to reduce csSet. */
   if (info.csSet > cSectors) info.csSet = cSectors;

   /* Truncate or grow the allocation of the file if needed. */
   cr = coreSuggestFileAllocation(pVolume, id, cSectors);
   if (cr) return cr;

   /* Update the file info. */
   cr = coreSetFileInfo(pVolume, id, &info);
   if (cr) return cr;

   /* Kill old data in the last set sector.  Otherwise, if the
      file grows later on, old data might re-appear. */
   if ((info.cbFileSize < cbOldSize) &&
       (info.cbFileSize < info.csSet * PAYLOAD_SIZE)) {
      offset = info.cbFileSize % PAYLOAD_SIZE;
      memset(zero, 0, PAYLOAD_SIZE - offset);
      cr = coreSetSectorData(pVolume, id, info.csSet - 1,
         offset, PAYLOAD_SIZE - offset, 0, zero);
      if (cr) return cr;
   }

   return CORERC_OK;
}
