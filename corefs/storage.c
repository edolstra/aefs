/* storage.c -- Storage and cache management.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: storage.c,v 1.14 2001/09/23 13:30:11 eelco Exp $

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
#include <math.h>
#include <assert.h>

#include "corefs.h"
#include "sysdep.h"


#define FILE_HASH_TABLE_SIZE    2048
#define SECTOR_HASH_TABLE_SIZE  8192
#define HASH_MULT_KNUTH         0.6180339887 /* (sqrt(5) - 1) / 2 */

#define MAX_STORAGE_FILE_NAME   12
#define MAX_STORAGE_PATH_NAME   \
   (MAX_VOLUME_BASE_PATH_NAME + MAX_STORAGE_FILE_NAME)


typedef struct _CryptedFile CryptedFile;
typedef struct _CryptedSector CryptedSector;

struct _CryptedVolume {
      char * pszBasePath;

      /* The cipher instance (key). */
      Key * pKey;

      /* The parameters. */
      CryptedVolumeParms parms;

      /* Hash table for finding CryptedFiles by ID. */
      CryptedFile * FileHashTable[FILE_HASH_TABLE_SIZE];

      /* Number of CryptedFiles. */
      unsigned int cCryptedFiles;

      /* Head and tail of the MRU list of CryptedFiles. */
      CryptedFile * pFirstFile;
      CryptedFile * pLastFile;

      /* Number of open storage files. */
      unsigned int cOpenStorageFiles;

      /* Head of the MRU list of CryptedFiles with open storage
         files. */
      CryptedFile * pFirstOpen;
      CryptedFile * pLastOpen;

      /* Hash table for finding CryptedSectors by (file-ID,
         sector-#). */
      CryptedSector * SectorHashTable[SECTOR_HASH_TABLE_SIZE];

      /* Total number of sectors in the cache. */
      unsigned int csInCache;

      /* Head and tail of the MRU list of cached sectors. */
      CryptedSector * pFirstSector;
      CryptedSector * pLastSector;
      
      /* Total number of dirty sectors in the cache. */
      unsigned int csDirty;
};

struct _CryptedFile {
      CryptedFileID id;

      CryptedVolume * pVolume;

      CryptedFile * pNextInHash;
      CryptedFile * pPrevInHash;

      CryptedFile * pNextInMRU;
      CryptedFile * pPrevInMRU;

      CryptedFile * pNextOpen;
      CryptedFile * pPrevOpen;
      File * pStorageFile;

      unsigned int csDirty;
      
      CryptedSector * pFirstSector;
};

struct _CryptedSector {
      SectorNumber sectorNumber;
      
      CryptedFile * pFile;

      CryptedSector * pNextInHash;
      CryptedSector * pPrevInHash;

      CryptedSector * pNextInFile;
      CryptedSector * pPrevInFile;

      CryptedSector * pNextInMRU;
      CryptedSector * pPrevInMRU;

      bool fDirty;

      CryptedSectorData data;
};


/* Forward declarations. */
static void deleteHighSectors(CryptedFile * pFile, SectorNumber s);
static CoreResult closeStorageFile(CryptedFile * pFile);
static CoreResult dropFile(CryptedFile * pFile);
static CoreResult flushSectors(unsigned int cSectors,
   CryptedSector * * papSectors);
static void dirtySector(CryptedVolume * pVolume,
   CryptedSector * pSector);


CoreResult sys2core(SysResult sr)
{
   switch (sr) {
      case SYS_OK: return CORERC_OK;
      case SYS_NOT_ENOUGH_MEMORY: return CORERC_NOT_ENOUGH_MEMORY;
      case SYS_INVALID_PARAMETER: return CORERC_INVALID_PARAMETER;
      default: return CORERC_SYS + sr;
   }
}

     
static inline unsigned int fileHashTableHash(CryptedFileID id)
{
   double dummy;
   return ((unsigned int) (FILE_HASH_TABLE_SIZE *
      modf(HASH_MULT_KNUTH * id, &dummy)))
      % FILE_HASH_TABLE_SIZE;
}


static inline unsigned int sectorHashTableHash(CryptedFileID id,
   SectorNumber nr)
{
   double dummy;
   return (id +
      (unsigned int) (SECTOR_HASH_TABLE_SIZE *
         modf(HASH_MULT_KNUTH * nr, &dummy)))
      % SECTOR_HASH_TABLE_SIZE;
}


static int cmpSectors(const void * p1, const void * p2)
{
   int d;
   d = (int) ((CryptedSector *) p1)->pFile -
       (int) ((CryptedSector *) p2)->pFile;
   if (d) 
      d = ((CryptedSector *) p1)->sectorNumber -
          ((CryptedSector *) p2)->sectorNumber;
   return d;
}


static void sortSectorList(unsigned int csSectors,
   CryptedSector * * papSectors)
{
   qsort(papSectors, csSectors, sizeof(CryptedSector *), cmpSectors);
}



/*
 * Volumes.
 */


void coreSetDefVolumeParms(CryptedVolumeParms * pParms)
{
   pParms->flCryptoFlags = 0;
   pParms->flOpenFlags = SOF_READWRITE | SOF_DENYWRITE |
      SOF_RANDOMSEQUENTIAL;
   memset(&pParms->cred, 0, sizeof(pParms->cred));
   pParms->fReadOnly = false;
   pParms->cMaxCryptedFiles = 512;
   pParms->cMaxOpenStorageFiles = 8;
   pParms->csMaxCached = 1024;
   pParms->csIOGranularity = 512;
   pParms->csISFGrow = 64;
   pParms->dirtyCallBack = 0;
   pParms->pUserData = 0;
}


CoreResult coreAccessVolume(char * pszBasePath, Key * pKey,
   CryptedVolumeParms * pParms, CryptedVolume * * ppVolume)
{
   unsigned int i;
   CryptedVolume * pVolume;

   /* Sanity checks on this build. */
   assert(MAX_BLOCK_SIZE >= 16);
   assert(sizeof(CryptedFileInfoOnDisk) + FILEINFO_RESERVED +
      MAX_INTERNAL_EAS == PAYLOAD_SIZE);
   assert(RANDOM_SIZE == 4);

   *ppVolume = 0;

   if (pParms->cMaxOpenStorageFiles < 1)
      return CORERC_INVALID_PARAMETER;
   
   if (strlen(pszBasePath) + 2 > MAX_VOLUME_BASE_PATH_NAME)
      return CORERC_INVALID_PARAMETER;
   
   /* Allocate the CryptedVolume. */
   pVolume = malloc(sizeof(CryptedVolume));
   if (!pVolume)
      return CORERC_NOT_ENOUGH_MEMORY;

   /* Init the CryptedVolume. */
   pVolume->pKey = pKey;
   pVolume->parms = *pParms;
   pVolume->cCryptedFiles = 0;
   pVolume->pFirstFile = 0;
   pVolume->pLastFile = 0;
   pVolume->cOpenStorageFiles = 0;
   pVolume->pFirstOpen = 0;
   pVolume->pLastOpen = 0;
   pVolume->csInCache = 0;
   pVolume->pFirstSector = 0;
   pVolume->pLastSector = 0;
   pVolume->csDirty = 0;
   
   for (i = 0; i < FILE_HASH_TABLE_SIZE; i++)
      pVolume->FileHashTable[i] = 0;
   
   for (i = 0; i < SECTOR_HASH_TABLE_SIZE; i++)
      pVolume->SectorHashTable[i] = 0;
   
   /* Copy the base path name. */
   pVolume->pszBasePath = malloc(strlen(pszBasePath) + 1);
   if (!pVolume->pszBasePath) {
      free(pVolume);
      return CORERC_NOT_ENOUGH_MEMORY;
   }
   strcpy(pVolume->pszBasePath, pszBasePath);

   if (pVolume->parms.fReadOnly)
       pVolume->parms.flOpenFlags = (pVolume->parms.flOpenFlags &
           ~SOF_RWMASK) | SOF_READONLY;

   *ppVolume = pVolume;

   return CORERC_OK;
}


/* Free the volume and all associated data from memory.  All dirty
   sectors are flushed to disk. */
CoreResult coreDropVolume(CryptedVolume * pVolume)
{
   CoreResult cr;
   unsigned int i;
   
   /* Drop all files.  This will flush all dirty sectors and close all
      open storage files. */
   for (i = 0; i < FILE_HASH_TABLE_SIZE; i++) {
      while (pVolume->FileHashTable[i]) {
         cr = dropFile(pVolume->FileHashTable[i]);
         if (cr) return cr; /* !!! Is this good? Drop anyway? */
      }
   }

   assert(pVolume->csInCache == 0);
   assert(pVolume->csDirty == 0);
                      
   /* Free the base path. */
   free(pVolume->pszBasePath);

   /* Free the CryptedVolume. */
   free(pVolume);
   
   return CORERC_OK;
}


/* Flush all dirty sectors in the cache to disk. */
CoreResult coreFlushVolume(CryptedVolume * pVolume)
{
   CoreResult cr;
   CryptedSector * * papDirty, * p, * * q;
   
   if (pVolume->csDirty) {
      
      papDirty = malloc(pVolume->csDirty * sizeof(CryptedSector *));
      if (!papDirty) return CORERC_NOT_ENOUGH_MEMORY;

      for (p = pVolume->pFirstSector, q = papDirty; p;
           p = p->pNextInMRU)
         if (p->fDirty) *q++ = p;

      sortSectorList(pVolume->csDirty, papDirty);

      cr = flushSectors(pVolume->csDirty, papDirty);
      free(papDirty);
      if (cr) return cr;
      assert(pVolume->csDirty == 0);
   }

   return CORERC_OK;
}


/* Reduce the number of CryptedFile structures maintained in memory to
   cFiles.  All references to CryptedFile structures on this volume
   may be invalid after calling this function. */
static CoreResult shrinkCryptedFiles(CryptedVolume * pVolume,
   unsigned int cFiles)
{
   CoreResult cr;

   while (pVolume->cCryptedFiles > cFiles) {
      cr = dropFile(pVolume->pLastFile);
      if (cr) return cr;
   }
   
   return CORERC_OK;
}


/* Reduce the number of open storage files to cFiles. */
CoreResult coreShrinkOpenStorageFiles(CryptedVolume * pVolume,
   unsigned int cFiles)
{
   CoreResult cr;

   while (pVolume->cOpenStorageFiles > cFiles) {
      cr = closeStorageFile(pVolume->pLastOpen);
      if (cr) return cr;
   }
   
   return CORERC_OK;
}


CryptedVolumeParms * coreQueryVolumeParms(CryptedVolume * pVolume)
{
   return &pVolume->parms;
}


void coreQueryVolumeStats(CryptedVolume * pVolume,
   CryptedVolumeStats * pStats)
{
   pStats->cCryptedFiles = pVolume->cCryptedFiles;
   pStats->cOpenStorageFiles = pVolume->cOpenStorageFiles;
   pStats->csInCache = pVolume->csInCache;
   pStats->csDirty = pVolume->csDirty;
}


/*
 * Files.
 */


/* Add the file at the head of the MRU list of CryptedFiles. */
static void addFileToMRUList(CryptedFile * p)
{
   CryptedVolume * v = p->pVolume;
   p->pNextInMRU = v->pFirstFile;
   p->pPrevInMRU = 0;
   if (p->pNextInMRU)
      p->pNextInMRU->pPrevInMRU = p;
   else
      v->pLastFile = p;
   v->pFirstFile = p;
   v->cCryptedFiles++;
}


/* Remove the file from the MRU list of CryptedFiles. */
static void removeFileFromMRUList(CryptedFile * p)
{
   CryptedVolume * v = p->pVolume;
   v->cCryptedFiles--;
   assert(v->cCryptedFiles >= 0);
   if (p->pPrevInMRU)
      p->pPrevInMRU->pNextInMRU = p->pNextInMRU;
   else
      v->pFirstFile = p->pNextInMRU;
   if (p->pNextInMRU)
      p->pNextInMRU->pPrevInMRU = p->pPrevInMRU;
   else
      v->pLastFile = p->pPrevInMRU;
}


static void makeStoragePathName(CryptedVolume * pVolume,
   CryptedFileID id, char * pszPathName)
{
   sprintf(pszPathName, "%s%08lx.enc",
      pVolume->pszBasePath, id);
}


/* Verify that the storage file for the specified CryptedFile
   exists. */
static CoreResult storageFileExists(CryptedVolume * pVolume,
   CryptedFileID id)
{
   char szPathName[MAX_STORAGE_PATH_NAME];
   SysResult sr;
   bool fExists;
   makeStoragePathName(pVolume, id, szPathName);
   if (sr = sysFileExists(szPathName, &fExists)) return sys2core(sr);
   return fExists ? CORERC_FILE_EXISTS : CORERC_OK;
}


/* Add a file to the head of the MRU list of open storage files. */
static void addFileToOpenList(CryptedFile * p)
{
   CryptedVolume * v = p->pVolume;
   p->pNextOpen = v->pFirstOpen;
   p->pPrevOpen = 0;
   if (p->pNextOpen)
      p->pNextOpen->pPrevOpen = p;
   else
      v->pLastOpen = p;
   v->pFirstOpen = p;
   v->cOpenStorageFiles++;
}


/* Remove a file from the MRU list of open storage files. */
static void removeFileFromOpenList(CryptedFile * p)
{
   CryptedVolume * v = p->pVolume;
   v->cOpenStorageFiles--;
   assert(v->cOpenStorageFiles >= 0);
   if (p->pPrevOpen)
      p->pPrevOpen->pNextOpen = p->pNextOpen;
   else
      v->pFirstOpen = p->pNextOpen;
   if (p->pNextOpen)
      p->pNextOpen->pPrevOpen = p->pPrevOpen;
   else
      v->pLastOpen = p->pPrevOpen;
}


/* Close a storage file. */
static CoreResult closeStorageFile(CryptedFile * pFile)
{
   File * pStorageFile;

   pStorageFile = pFile->pStorageFile;

   if (!pStorageFile) return CORERC_OK;

   pFile->pStorageFile = 0;
   
   /* Remove the file from the list of open files. */
   removeFileFromOpenList(pFile);

   /* Close the storage file. */
   return sys2core(sysCloseFile(pStorageFile));
}


/* Make sure that the storage file for the specified CryptedFile is
   open.  If it is already open, it is moved to the head of the MRU
   list.  If it is not open, it is opened or created. */
static CoreResult openStorageFile(CryptedFile * pFile, bool fCreate,
   CryptedFilePos cbInitialSize)
{
   CoreResult cr;
   SysResult sr;
   char szPathName[MAX_STORAGE_PATH_NAME];
   
   if (pFile->pStorageFile) {
      /* pFile is now the CryptedFile with the most recently used open
         storage file, so move it to the head of the MRU list. */
      removeFileFromOpenList(pFile);
      addFileToOpenList(pFile);
      return CORERC_OK;
   }

   if (pFile->pVolume->cOpenStorageFiles >=
      pFile->pVolume->parms.cMaxOpenStorageFiles) {
      /* We have reached the maximum number of concurrently open
         storage file.  Close the least recently used. */
      cr = coreShrinkOpenStorageFiles(pFile->pVolume,
         pFile->pVolume->parms.cMaxOpenStorageFiles - 1);
      if (cr) return cr;
   }

   /* Open/create the storage file. */
   
   makeStoragePathName(pFile->pVolume, pFile->id, szPathName);

   if (fCreate)
      sr = sysCreateFile(szPathName,
           pFile->pVolume->parms.flOpenFlags, cbInitialSize, 
           pFile->pVolume->parms.cred, &pFile->pStorageFile);
   else
      sr = sysOpenFile(szPathName,
           pFile->pVolume->parms.flOpenFlags,
           pFile->pVolume->parms.cred, &pFile->pStorageFile);
   
   if (sr) return sys2core(sr);

   /* Add at the head of the MRU list. */
   addFileToOpenList(pFile);
   
   return CORERC_OK;
}


/* Create a CryptedFile object for the specified file ID (or return it
   if it already exists).  This function does not check that the
   associated storage file exists and is readable. */
static CoreResult accessFile(CryptedVolume * pVolume,
   CryptedFileID id, CryptedFile * * ppFile)
{
   unsigned int hash;
   CryptedFile * pFile;

   if (id == 0) return CORERC_INVALID_PARAMETER;
   
   /* Search in the volume's CryptedFile hash table for a CryptedFile
      with the specified file ID. */
   hash = fileHashTableHash(id);
   for (*ppFile = pVolume->FileHashTable[hash];
        *ppFile;
        *ppFile = (*ppFile)->pNextInHash)
      if ((*ppFile)->id == id) {
         /* Move file to front of MRU list. */
         removeFileFromMRUList(*ppFile);
         addFileToMRUList(*ppFile);
         return CORERC_OK;
      }

   *ppFile = 0;

   if (pVolume->cCryptedFiles >= pVolume->parms.cMaxCryptedFiles)
      shrinkCryptedFiles(pVolume, pVolume->parms.cMaxCryptedFiles - 1);
   
   /* Didn't find anything, so we create a new CryptedFile. */
   pFile = sysAllocSecureMem(sizeof(CryptedFile));
   if (!pFile)
      return CORERC_NOT_ENOUGH_MEMORY;

   /* Init it. */
   pFile->pVolume = pVolume;
   pFile->id = id;
   pFile->pNextOpen = 0;
   pFile->pPrevOpen = 0;
   pFile->pStorageFile = 0;
   pFile->csDirty = 0;
   pFile->pFirstSector = 0;

   /* Add the file to the volume's MRU list. */
   addFileToMRUList(pFile);
      
   /* Add the file to the volume's CryptedFile hash table. */
   pFile->pNextInHash = pVolume->FileHashTable[hash];
   if (pFile->pNextInHash)
      pFile->pNextInHash->pPrevInHash = pFile;
   pFile->pPrevInHash = 0;
   pVolume->FileHashTable[hash] = pFile;

   *ppFile = pFile;

   return CORERC_OK;
}


/* Remove the CryptedFile from memory.  All dirty sectors are flushed
   to disk and removed from the cache. */
static CoreResult dropFile(CryptedFile * pFile)
{
   CoreResult cr;

   cr = coreFlushFile(pFile->pVolume, pFile->id);
   if (cr) return cr; /* !!! */
   
   /* Delete all sectors from the cache. */
   deleteHighSectors(pFile, 0);

   /* Close the storage file, if we have one. */
   cr = closeStorageFile(pFile);
   if (cr) return cr; /* !!! */
   
   /* Remove the file from the volume's MRU list. */
   removeFileFromMRUList(pFile);
   
   /* Remove the CryptedFile from the volume's file hash table. */
   if (pFile->pPrevInHash)
      pFile->pPrevInHash->pNextInHash = pFile->pNextInHash;
   else
      pFile->pVolume->FileHashTable[fileHashTableHash(pFile->id)] =
         pFile->pNextInHash;
   if (pFile->pNextInHash)
      pFile->pNextInHash->pPrevInHash = pFile->pPrevInHash;

   /* Free the CryptedFile. */
   sysFreeSecureMem(pFile);

   return CORERC_OK;
}


/* Create a file with the given ID and initial size. The content of
   the allocated sectors is undefined (and reading them will give a
   CRC error with high probability).  The initial size is advisory
   only (see coreSuggestFileSize). */
CoreResult coreCreateFile(CryptedVolume * pVolume,
   CryptedFileID id, SectorNumber csPreallocate)
{
   CoreResult cr;
   CryptedFile * pFile;

   if (pVolume->parms.fReadOnly) return CORERC_READ_ONLY;

   if (storageFileExists(pVolume, id)) return CORERC_ID_EXISTS;

   /* Create a CryptedFile for this file. */
   cr = accessFile(pVolume, id, &pFile);
   if (cr) return cr;

   /* Create a storage file. */
   cr = openStorageFile(pFile, true, csPreallocate * SECTOR_SIZE);
   if (cr) {
      dropFile(pFile);
      return cr;
   }

   return CORERC_OK;
}


/* Destroy the specified file.  This means freeing all the file's
   resources in memory (see dropFile()) and deleting the
   associated storage file. */
CoreResult coreDestroyFile(CryptedVolume * pVolume, CryptedFileID id)
{
   CoreResult cr;
   char szPathName[MAX_STORAGE_PATH_NAME];
   CryptedFile * pFile;

   if (pVolume->parms.fReadOnly) return CORERC_READ_ONLY;

   cr = accessFile(pVolume, id, &pFile);
   if (cr) return cr;

   makeStoragePathName(pVolume, pFile->id, szPathName);

   /* Delete all the file's sectors from the cache without flushing to
      disk. */
   deleteHighSectors(pFile, 0);
   
   /* Drop the crypted file.  This will close the storage file. */
   cr = dropFile(pFile);
   if (cr) return cr;

   /* Delete the storage file. */
   return sys2core(sysDeleteFile(szPathName, true, pVolume->parms.cred));
}


/* Flush all dirty sectors. */
CoreResult coreFlushFile(CryptedVolume * pVolume, CryptedFileID id)
{
   CoreResult cr;
   CryptedSector * * papDirty, * p, * * q;
   CryptedFile * pFile;

   cr = accessFile(pVolume, id, &pFile);
   if (cr) return cr;

   if (pFile->csDirty) {

      papDirty = malloc(pFile->csDirty * sizeof(CryptedSector *));
      if (!papDirty) return CORERC_NOT_ENOUGH_MEMORY;

      for (p = pFile->pFirstSector, q = papDirty; p;
           p = p->pNextInFile)
         if (p->fDirty) *q++ = p;

      sortSectorList(pFile->csDirty, papDirty);

      cr = flushSectors(pFile->csDirty, papDirty);
      free(papDirty);
      if (cr) return cr;
      assert(pFile->csDirty == 0);
   }

   return CORERC_OK;
}


/* Suggest that the size of the storage file be increased or decreased
   to the specified number of sectors.  This can be used to improve
   performance and reduce fragmentation on certain systems (like
   OS/2). */
CoreResult coreSuggestFileAllocation(CryptedVolume * pVolume,
   CryptedFileID id, SectorNumber csAllocate)
{
   CoreResult cr;
   FilePos cbNewSize;
   CryptedFile * pFile;

   if (pVolume->parms.fReadOnly) return CORERC_READ_ONLY;

   cr = accessFile(pVolume, id, &pFile);
   if (cr) return cr;

   deleteHighSectors(pFile, csAllocate);
   
   /* Make sure the storage file for this CryptedFile is open. */
   cr = openStorageFile(pFile, false, 0);
   if (cr) return cr;

   /* Set the new file size.  The semantics of sysSetFileSize() do not
      guarantee that growing a file will work (and it doesn't, in
      general, on POSIX).  */
   cbNewSize = SECTOR_SIZE * (CryptedFilePos) csAllocate;
   return sys2core(sysSetFileSize(pFile->pStorageFile, cbNewSize));
}


/*
 * Sectors & cache management.
 */


/* Clear the dirty flag of the specified sector. */
static void clearDirtyFlag(CryptedSector * p)
{
   CryptedVolume * pVolume = p->pFile->pVolume;
   if (p->fDirty) {
      p->fDirty = false;
      p->pFile->csDirty--;
      pVolume->csDirty--;
      assert(p->pFile->csDirty >= 0);
      assert(pVolume->csDirty >= 0);
      if (pVolume->csDirty == 0 && pVolume->parms.dirtyCallBack)
         pVolume->parms.dirtyCallBack(pVolume, false);
   }
}


/* Add the sector at the head of the MRU list of cached sectors. */
static void addSectorToMRUList(CryptedSector * p)
{
   CryptedVolume * v = p->pFile->pVolume;
   p->pNextInMRU = v->pFirstSector;
   p->pPrevInMRU = 0;
   if (p->pNextInMRU)
      p->pNextInMRU->pPrevInMRU = p;
   else
      v->pLastSector = p;
   v->pFirstSector = p;
}


/* Remove the sector from the MRU list of cached sectors. */
static void removeSectorFromMRUList(CryptedSector * p)
{
   CryptedVolume * v = p->pFile->pVolume;
   if (p->pPrevInMRU)
      p->pPrevInMRU->pNextInMRU = p->pNextInMRU;
   else
      v->pFirstSector = p->pNextInMRU;
   if (p->pNextInMRU)
      p->pNextInMRU->pPrevInMRU = p->pPrevInMRU;
   else
      v->pLastSector = p->pPrevInMRU;
}


/* Add a sector to the cache.  The sector data is undefined.  The
   dirty flag is initially false. */
static CoreResult addSector(CryptedFile * pFile, SectorNumber s,
   CryptedSector * * ppSector)
{
   CryptedSector * pSector;
   unsigned int hash;

   *ppSector = 0;
   
   pSector = sysAllocSecureMem(sizeof(CryptedSector));
   if (!pSector) return CORERC_NOT_ENOUGH_MEMORY;

   pSector->pFile = pFile;
   pSector->sectorNumber = s;
   pSector->fDirty = false;

   pFile->pVolume->csInCache++;
   
   addSectorToMRUList(pSector);

   /* Insert the newly created CryptedSector into the linked
      list of this file's CryptedSectors. */
   pSector->pNextInFile = pFile->pFirstSector;
   pSector->pPrevInFile = 0;
   if (pSector->pNextInFile)
      pSector->pNextInFile->pPrevInFile = pSector;
   pFile->pFirstSector = pSector;

   /* Add to the volume's CryptedFile hash table. */
   hash = sectorHashTableHash(pFile->id, s);
   pSector->pNextInHash = pFile->pVolume->SectorHashTable[hash];
   if (pSector->pNextInHash)
      pSector->pNextInHash->pPrevInHash = pSector;
   pSector->pPrevInHash = 0;
   pFile->pVolume->SectorHashTable[hash] = pSector;

   *ppSector = pSector;

   return CORERC_OK;
}


/* Return a sector from the cache.  The sector is moved to the head of
   the MRU list.  Return 0 if the sector is not presently in the
   cache. */
static CryptedSector * queryCachedSector(CryptedVolume * pVolume,
   CryptedFileID id, SectorNumber sectorNumber)
{
   unsigned int hash;
   CryptedSector * pSector;

   /* Search in the volume's CryptedFile hash table for a CryptedFile
      with the specified file ID. */
   hash = sectorHashTableHash(id, sectorNumber);
   for (pSector = pVolume->SectorHashTable[hash];
        pSector;
        pSector = pSector->pNextInHash)
      if ((pSector->sectorNumber == sectorNumber) &&
          (pSector->pFile->id == id))
      {
         removeSectorFromMRUList(pSector);
         addSectorToMRUList(pSector);
         return pSector;
      }

   return 0; /* sector not in cache */
}


/* Delete the specified sector from the cache. */
static void deleteSector(CryptedSector * p)
{
   if (p->fDirty) clearDirtyFlag(p);

   p->pFile->pVolume->csInCache--;
   assert(p->pFile->pVolume->csInCache >= 0);

   removeSectorFromMRUList(p);

   /* Remove the sector from the volume's sector hash table. */
   if (p->pPrevInHash)
      p->pPrevInHash->pNextInHash = p->pNextInHash;
   else
      p->pFile->pVolume->SectorHashTable[sectorHashTableHash(
         p->pFile->id, p->sectorNumber)] = p->pNextInHash;
   if (p->pNextInHash)
      p->pNextInHash->pPrevInHash = p->pPrevInHash;
   
   /* Remove the sector from the file's linked list of sectors. */
   if (p->pPrevInFile)
      p->pPrevInFile->pNextInFile = p->pNextInFile;
   else
      p->pFile->pFirstSector = p->pNextInFile;
   if (p->pNextInFile)
      p->pNextInFile->pPrevInFile = p->pPrevInFile;

   /* Free the sector. */
   sysFreeSecureMem(p);
}


/* Delete all the file's sectors with sector numbers >= s from the
   cache, without flushing dirty sectors to disk. */
static void deleteHighSectors(CryptedFile * pFile, SectorNumber s)
{
   CryptedSector * p, * pnext;
   for (p = pFile->pFirstSector; p; p = pnext) {
      pnext = p->pNextInFile;
      if (p->sectorNumber >= s) deleteSector(p);
   }
}


/* Delete sectors from the cache to make room for csReq new sectors,
   flushing dirty sectors to disk if necessary.  Do not delete sectors
   in the exclusion region (i.e. the sectors being fetched by
   coreFetchSectors()). */
static CoreResult purgeCache(CryptedVolume * pVolume, unsigned int csReq,
   CryptedFile * pExclFile, SectorNumber sExclStart,
   SectorNumber sExclExtent)
{
   CryptedSector * p = pVolume->pLastSector, * pnext;
   CoreResult cr;

   /* We simply delete the least recently used sectors from the cache
      (skipping sectors in the exclusion region).  If any of those
      sectors is dirty, *all* dirty sectors in the cache are flushed
      to disk. */

   while (csReq--) {

      while (
         p &&
         (p->pFile == pExclFile) &&
         (p->sectorNumber >= sExclStart) &&
         (p->sectorNumber < sExclStart + sExclExtent))
         p = p->pPrevInMRU;
      assert(p);

      if (p->fDirty) { /* should happen at most once */ 
         cr = coreFlushVolume(pVolume);
         if (cr) return cr;
      }

      pnext = p->pPrevInMRU;
      deleteSector(p);
      p = pnext;
   }

   return CORERC_OK;
}


/* Read ciphertext from the specified location. */
static CoreResult readBuffer(CryptedFile * pFile,
   SectorNumber sStart, SectorNumber csExtent, octet * pabBuffer)
{
   CoreResult cr;
   SysResult sr;
   FilePos cbRead;

   cr = openStorageFile(pFile, false, 0);
   if (cr) return cr;
         
   if (sr = sysSetFilePos(pFile->pStorageFile, SECTOR_SIZE *
      (CryptedFilePos) sStart))
      return sys2core(sr);
   
   if (sr = sysReadFromFile(pFile->pStorageFile,
      SECTOR_SIZE * csExtent, pabBuffer, &cbRead) ||
      (cbRead != SECTOR_SIZE * csExtent))
      return sys2core(sr);

   return CORERC_OK;
}

   
/* Read an extent of sectors into the cache. */
static CoreResult readSectorExtent(CryptedFile * pFile,
   SectorNumber sStart, SectorNumber csExtent, unsigned int flFlags)
{
   CoreResult cr, crfinal = CORERC_OK;
   octet * pabBuffer, * p;
   SectorNumber i;
   CryptedSector * pSector;
   
   pabBuffer = malloc(csExtent * SECTOR_SIZE);
   if (!pabBuffer) return CORERC_NOT_ENOUGH_MEMORY;

   cr = readBuffer(pFile, sStart, csExtent, pabBuffer);
   if (cr) {
      free(pabBuffer);
      return cr;
   }

   for (i = sStart, p = pabBuffer;
        i < sStart + csExtent;
        i++, p += SECTOR_SIZE)
   {
      cr = addSector(pFile, i, &pSector);
      if (cr) {
         free(pabBuffer);
         return cr;
      }

      cr = coreDecryptSectorData(p, &pSector->data,
         pFile->pVolume->pKey, pFile->pVolume->parms.flCryptoFlags);
      if (cr) {
         if (flFlags & CFETCH_ADD_BAD)
            crfinal = cr;
         else {
            deleteSector(pSector);
            free(pabBuffer);
            return cr;
         }
      }
   }
   
   free(pabBuffer);
   return crfinal;
}


/* Read the specified sectors of the specified file into the cache.
   Adjacent sectors are read in a single read operation. */
static CoreResult readSectors(CryptedFile * pFile,
   unsigned int csRead, SectorNumber * pasRead, unsigned int flFlags)
{
   CoreResult cr, crfinal = CORERC_OK;
   CryptedSector * pSector;
   unsigned int c;
   
   while (csRead) {

      if (flFlags & CFETCH_NO_READ) {

         cr = addSector(pFile, *pasRead, &pSector);
         if (cr) return cr;

         dirtySector(pFile->pVolume, pSector);
         memset(&pSector->data, 0, sizeof(CryptedSectorData));
         
         c = 1;
         
      } else {
      
         /* How many adjacent sectors? */
         for (c = 1;
              (c < csRead) && (pasRead[c] == *pasRead + c);
              c++);

         cr = readSectorExtent(pFile, *pasRead, c, flFlags);
         if (cr) {
            if ((cr == CORERC_BAD_CHECKSUM) &&
               (flFlags & CFETCH_ADD_BAD))
               crfinal = cr;
            else
               return cr;
         }
      }
      
      csRead -= c, pasRead += c;
   }

   return crfinal;
}


/* Fetch sectors from the specified file.  csExtent may not be larger
   than the maximum cache size. */
CoreResult coreFetchSectors(CryptedVolume * pVolume,
   CryptedFileID id, SectorNumber sStart, SectorNumber csExtent,
   unsigned int flFlags)
{
   CoreResult cr;
   SectorNumber i;
   unsigned int csMissing;
   SectorNumber * pasMissing;
   CryptedFile * pFile;

   cr = accessFile(pVolume, id, &pFile);
   if (cr) return cr;
   
   if (!csExtent) return CORERC_OK;
   if (csExtent > pFile->pVolume->parms.csMaxCached)
      return CORERC_CACHE_OVERFLOW;

   /* Determine which sectors are not in the cache. */
   pasMissing = malloc(csExtent * sizeof(SectorNumber *));
   if (!pasMissing) return CORERC_NOT_ENOUGH_MEMORY;
   csMissing = 0;
   for (i = 0; i < csExtent; i++)
      if (!queryCachedSector(pVolume, id, sStart + i)) 
         pasMissing[csMissing++] = sStart + i;

   if (!csMissing) { /* everything already in cache */
      free(pasMissing);
      return CORERC_OK;
   }

   /* Make sure that there is enough room in the cache. */
   if (pFile->pVolume->csInCache + csMissing >
      pFile->pVolume->parms.csMaxCached)
   {
      cr = purgeCache(pFile->pVolume,
         pFile->pVolume->csInCache -
         (pFile->pVolume->parms.csMaxCached - csMissing),
         pFile, sStart, csExtent);
      if (cr) {
         free(pasMissing);
         return cr;
      }
   }

   cr = readSectors(pFile, csMissing, pasMissing, flFlags);
   free(pasMissing);
   return cr;
}


/* Write ciphertext to the specified location. */
static CoreResult writeBuffer(CryptedSector * pStart, unsigned int c,
   octet * pabBuffer)
{
   CoreResult cr;
   SysResult sr;
   FilePos cbWritten;
   
   assert(!pStart->pFile->pVolume->parms.fReadOnly);

   cr = openStorageFile(pStart->pFile, false, 0);
   if (cr) return cr;
         
   if (sr = sysSetFilePos(pStart->pFile->pStorageFile, SECTOR_SIZE *
      (CryptedFilePos) pStart->sectorNumber))
      return sys2core(sr);

   if (sr = sysWriteToFile(pStart->pFile->pStorageFile,
      SECTOR_SIZE * c, pabBuffer, &cbWritten) ||
      (cbWritten != SECTOR_SIZE * c))
      return sys2core(sr);

   return CORERC_OK;
}


/* Flush the specified sectors to disk.  Dirty sectors are ignored.
   It is advisable to sort the list of sectors by file and sector
   number, since adjacent sectors in the list are written in one write
   operation. */
static CoreResult flushSectors(unsigned int cSectors,
   CryptedSector * * papSectors)
{
   CoreResult cr;
   CryptedSector * pStart;
   unsigned int c, i;
   octet * pabBuffer, * p;

   while (cSectors) {

      if ((pStart = *papSectors)->fDirty) {

         /* How many adjacent sectors? */
         for (c = 1;
              (c < cSectors) &&
                 (papSectors[c]->fDirty) &&
                 (papSectors[c]->pFile == pStart->pFile) &&
                 (papSectors[c]->sectorNumber ==
                    pStart->sectorNumber + c);
              c++);

         /* Write c sectors to disk at once.  Allocate a buffer to
            hold the ciphertext, encrypt the sectors into the buffer,
            and write the buffer. */

         while (1) {
            pabBuffer = malloc(SECTOR_SIZE * c);
            if (pabBuffer) break;
            if (--c) return CORERC_NOT_ENOUGH_MEMORY;
         }

         for (i = 0, p = pabBuffer; i < c; i++, p += SECTOR_SIZE) {
            coreEncryptSectorData(&papSectors[i]->data, p,
               pStart->pFile->pVolume->pKey,
               pStart->pFile->pVolume->parms.flCryptoFlags);
         }

         cr = writeBuffer(pStart, c, pabBuffer);
         free(pabBuffer);
         if (cr) return cr;

         for (i = 0; i < c; i++)
            clearDirtyFlag(papSectors[i]);
         
      } else c = 1;
      
      while (c) c--, cSectors--, papSectors++;
   }

   return CORERC_OK;
}


/* Flush the specified sector to disk, if it's in the cache and
   dirty.  Otherwise, do nothing and return CORERC_OK. */
CoreResult coreFlushSector(CryptedVolume * pVolume,
   CryptedFileID id, SectorNumber s)
{
   CryptedSector * pSector;
   pSector = queryCachedSector(pVolume, id, s);
   return pSector ? flushSectors(1, &pSector) : CORERC_OK;
}


/* Set the sector's dirty flag. */
static void dirtySector(CryptedVolume * pVolume,
   CryptedSector * pSector)
{
   if (!pSector->fDirty) {
      pSector->fDirty = true;
      pSector->pFile->csDirty++;
      if (pVolume->csDirty++ == 0 && pVolume->parms.dirtyCallBack)
         pVolume->parms.dirtyCallBack(pVolume, true);
   }
}


/* Store a range of bytes from a file sector into the specified
   buffer. */
CoreResult coreQuerySectorData(CryptedVolume * pVolume,
   CryptedFileID id, SectorNumber s, unsigned int offset,
   unsigned int bytes, unsigned int flFlags, void * pBuffer)
{
   CoreResult cr;
   CryptedSector * pSector;
   
   if (offset + bytes > PAYLOAD_SIZE)
      return CORERC_INVALID_PARAMETER;
   
   cr = coreFetchSectors(pVolume, id, s, 1, flFlags);
   if (cr && ((cr != CORERC_BAD_CHECKSUM) |
      !(flFlags & CFETCH_ADD_BAD)))
      return cr;
   
   pSector = queryCachedSector(pVolume, id, s);
   assert(pSector);

   memcpy(pBuffer, pSector->data.payload + offset, bytes);
   
   return cr;
}


/* Store the specified buffer into a range of bytes of a file sector.
   The sector is marked dirty.  If bytes == 0, the sector is marked
   dirty only if it is in the cache; no error is returned in either
   case. */
CoreResult coreSetSectorData(CryptedVolume * pVolume,
   CryptedFileID id, SectorNumber s, unsigned int offset,
   unsigned int bytes, unsigned int flFlags, void * pBuffer)
{
   CoreResult cr;
   CryptedSector * pSector;
   
   if (pVolume->parms.fReadOnly) return CORERC_READ_ONLY;

   if (offset + bytes > PAYLOAD_SIZE)
      return CORERC_INVALID_PARAMETER;

   if (bytes == 0) {
      pSector = queryCachedSector(pVolume, id, s);
      if (pSector) dirtySector(pVolume, pSector);
      return CORERC_OK;
   }
   
   cr = coreFetchSectors(pVolume, id, s, 1, flFlags);
   if (cr && ((cr != CORERC_BAD_CHECKSUM) ||
      !(flFlags & CFETCH_ADD_BAD)))
      return cr;
   
   pSector = queryCachedSector(pVolume, id, s);
   assert(pSector);

   memcpy(pSector->data.payload + offset, pBuffer, bytes);

   dirtySector(pVolume, pSector);
   
   return cr;
}
