/* aefsck.c -- AEFS file system check and repair program.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: aefsck.c,v 1.16 2001/09/23 13:30:24 eelco Exp $

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
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <time.h>
#include <errno.h>

#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include "getopt.h"

#include "sysdep.h"
#include "corefs.h"
#include "coreutils.h"
#include "superblock.h"
#include "ciphertable.h"

#include "utilutils.h"
#include "aefsck.h"


#define STOP(res) ((res) & (AEFSCK_ABORT | AEFSCK_FAIL | AEFSCK_INTERRUPT))


/* Fix flags */
#define FSCK_FIX             1  /* fix most errors */
#define FSCK_FORCEFIX        2  /* apply `dangerous' fixes */
#define FSCK_SURFACESCAN     16 /* check every sector in every storage
                                   file for CRC errors */
#define FSCK_VERBOSE         32 /* show progress */


/* Flags for FSItem.flags. */
#define FSI_IGNORE           1
#define FSI_REWRITEDIR       2


/* Result codes for ask(). */
#define ASK_NO               0
#define ASK_YES              1


/* FSItem holds info about a file. */
typedef struct _FSItem FSItem;

struct _FSItem {
      FSItem * pNextInHash;
      FSItem * pNextSorted;
      CryptedFileID id;
      CryptedFileInfo info;
      unsigned int cRefs;
      CryptedFileID idParent;
      unsigned int flags;
      CryptedDirEntry * pChildren;
      CryptedFilePos cbStorageSize;
};


#define FSIHASHTAB 4096
#define hashfsi(id) (id % FSIHASHTAB)

/* State holds all relevant info. */
typedef struct {
      unsigned int flags;
      
      SuperBlock * pSuperBlock;
      CryptedVolume * pVolume; /* convenience */
      
      FSItem * fsihashtab[FSIHASHTAB];
      
      CryptedFileID idLostFound;
      
      CoreResult readcr;
      
      SectorNumber csISFSize;
      
      unsigned int cFiles;
      FSItem * pFirstSorted;
      
      bool fRewriteFreeList;
      char * pFreeList;
} State;


/* User interrupt? */
static bool fInterrupted = false;


/* Ask the user a question.  `No' should always be the `safe'
   answer. */
static int ask(char * pszMsg, ...)
{
   char c;
   int res;
   char szLine[128];
   va_list args;
   va_start(args, pszMsg);
   vprintf(pszMsg, args);
   va_end(args);
   printf(" (y/N) > ");
   if (fgets(szLine, sizeof(szLine), stdin) == 0)
      return ASK_NO;
   res = sscanf(szLine, " %c \n", &c);
   if (res != 1) return ASK_NO;
   return (c == 'y' || c == 'Y') ? ASK_YES : ASK_NO;
}


/* Commit the superblocks. */
static int writeSuperBlock(SuperBlock * pSuperBlock)
{
   CoreResult cr;
   if (cr = coreWriteSuperBlock(pSuperBlock, 0)) {
      printf("superblock: error writing: %s\n", core2str(cr));
      return AEFSCK_ABORT;
   }
   return 0;
}


/* Check the superblock for errors.  Undecryptable or non-existing
   superblocks are only fixed if FSCK_FORCEFIX is specified and after
   user confirmation. */
static int checkSuperBlock(State * pState)
{
   SuperBlock * pSuperBlock = pState->pSuperBlock;
   char szKeyWarning[] =
      "(Make sure you specified the right key!  Otherwise I will "
      "trash the entire file system!)";
   int res = 0, res2;
   time_t now;

   if (pState->flags & FSCK_VERBOSE)
      printf("phase: checking superblock...\n");
   
   switch (pState->readcr) {
      case CORERC_OK:
         break;

      case CORERC_FILE_NOT_FOUND:
         res |= AEFSCK_ERRORFOUND;
         printf("superblock: encrypted part doesn't exist\n");
         if ((pState->flags & FSCK_FORCEFIX) &&
             ask("Attemp superblock reconstruction?  %s", szKeyWarning)
                == ASK_YES)
         {
            pSuperBlock->idRoot = 0; /* will force root creation */
            strcpy(pSuperBlock->szLabel, "FIXED");
            time(&now);
            strftime(pSuperBlock->szDescription,
               sizeof(pSuperBlock->szDescription),
               "Superblock reconstructed on %a, %d %b %Y %H:%M:%S UTC",
               gmtime(&now));
            if (res2 = writeSuperBlock(pSuperBlock))
               res = res | res2 | AEFSCK_ABORT;
         } else {
            printf(
               "Cannot proceed.  Specify `--force-fix' to attempt "
               "reconstruction of the superblock.\n");
            return res | AEFSCK_ABORT;
         }
         break;
         
      case CORERC_BAD_CHECKSUM:
         res |= AEFSCK_ERRORFOUND;
         if (pSuperBlock->magic == SUPERBLOCK2_MAGIC)
            printf(
               "superblock: bad checksum, good magic number "
               "(the key is very probably correct)\n");
         else
            printf(
               "superblock: bad checksum, bad magic number "
               "(the key is probably wrong)\n");
         if ((pState->flags & FSCK_FORCEFIX) &&
             ask("Rewrite superblock?  %s", szKeyWarning) == ASK_YES)
         {
            if (res2 = writeSuperBlock(pSuperBlock))
               res = res | res2 | AEFSCK_ABORT;
         } else {
            printf(
               "Cannot proceed.  Specify `--force-fix' to fix the "
               "superblock.\n");
            return res | AEFSCK_ABORT;
         }
         break;

      case CORERC_BAD_VERSION:
         res |= AEFSCK_ERRORFOUND;
         printf("superblock: incorrect version\n");
         if ((pState->flags & FSCK_FORCEFIX) &&
             ask("Reset version number?  (You probably should be "
                 "using a newer aefsck.)") == ASK_YES)
         {
            if (res2 = writeSuperBlock(pSuperBlock))
               res = res | res2 | AEFSCK_ABORT;
         } else {
            printf("Will not proceed.  Use a newer aefsck.\n");
            return res | AEFSCK_ABORT;
         }
         break;
         
      default:
         printf("superblock: cannot access superblock: %s\n",
            core2str(pState->readcr));
         return AEFSCK_FAIL;
   }

   return res;
}


/* Look up a file in the file hash table. */
static FSItem * findFile(State * pState, CryptedFileID id)
{
   FSItem * fsi;
   for (fsi = pState->fsihashtab[hashfsi(id)]; fsi;
        fsi = fsi->pNextInHash)
      if (fsi->id == id) return fsi;
   return 0;
}


/* Add a file to the file hash table. */
static FSItem * addFile(State * pState, CryptedFileID id)
{
   FSItem * fsi;
   unsigned int h = hashfsi(id);

   if (findFile(pState, id)) {
      printf("file %08lx: already in hash table\n", id);
      return 0;
   }
   
   if (!(fsi = malloc(sizeof(FSItem)))) {
      printf("file %08lx: out of memory\n", id);
      return 0;
   }

   memset(fsi, 0, sizeof(FSItem));
   fsi->pNextInHash = pState->fsihashtab[h];
   pState->fsihashtab[h] = fsi;
   fsi->pNextSorted = 0;
   fsi->id = id;
   fsi->pChildren = 0;

   pState->cFiles++;

   return fsi;
}


static char * printFileName2(State * pState, CryptedFileID id,
   char * p)
{
   CryptedDirEntry * pEntry;
   FSItem * fsi, * fsip;
   bool fFound;
   
   if (!id) {
      strcpy(p, "???");
   } else if (id == pState->pSuperBlock->idRoot) {
      *p = 0;
   } else {
      fsi = findFile(pState, id);
      if (!fsi) {
         sprintf(p, "$%08lx", id);
      } else {
         printFileName2(pState, fsi->idParent, p);
         fFound = false;
         fsip = findFile(pState, fsi->idParent);
         if (fsip) {
            for (pEntry = fsip->pChildren; pEntry;
                 pEntry = pEntry->pNext)
               if (pEntry->idFile == fsi->id) {
                  sprintf(strchr(p, 0), "/%s",
                     (char *) pEntry->pabName);
                  fFound = true;
                  break;
               }
         }
         if (!fFound)
            sprintf(strchr(p, 0), "/$%08lx", id);
      }
   }

   return p;
}


static char * printFileName(State * pState, CryptedFileID id)
{
   /* !!! check for buffer overflow */
   /* !!! check for cycles in idParent graph */
   static char szBuffer[16384]; 
   FSItem * fsi;
   
   if (id == pState->pSuperBlock->idRoot) {
      strcpy(szBuffer, "directory /");
   } else {
      fsi = findFile(pState, id);
      if (fsi) {
         if (CFF_ISEA(fsi->info.flFlags)) {
            strcpy(szBuffer, "extended attributes of ");
            printFileName2(pState, fsi->idParent, strchr(szBuffer, 0));
         } else {
            switch (fsi->info.flFlags & CFF_IFMT) {
               case CFF_IFDIR: strcpy(szBuffer, "directory "); break;
               default: strcpy(szBuffer, "file "); break;
            }
            printFileName2(pState, id, strchr(szBuffer, 0));
         }
      } else
         sprintf(szBuffer, "file $%08lx", id);
   }

   return szBuffer;
}


static void makeStorageName(State * pState, CryptedFileID id,
   char * szBuffer)
{
   assert(strlen(pState->pSuperBlock->pszBasePath) <=
      MAX_VOLUME_BASE_PATH_NAME);
   sprintf(szBuffer, "%s%08lx.enc",
      pState->pSuperBlock->pszBasePath, id);
}


/* Read the storage directory and look for storage files.  Add them to
   the file hash table. */
static int addFiles(State * pState)
{
   int res = 0, bad;
   unsigned int i;
   DIR * dir;
   struct dirent * dirent;
   struct stat st;
   char szName[MAX_VOLUME_BASE_PATH_NAME + 16];
   CryptedFileID id;
   FSItem * fsi;
   
   pState->cFiles = 0;
   
   if (!(dir = opendir(pState->pSuperBlock->pszBasePath))) {
      printf("filesystem: %s, aborting\n", strerror(errno));
      return res | AEFSCK_ABORT;
   }

   while (dirent = readdir(dir)) {

      if (fInterrupted) {
         closedir(dir);
         return res | AEFSCK_INTERRUPT;
      }
      
      /* Should add code for case-sensitive operating systems
         (Unix).  Corefs expects storage files to be in lower case,
         i.e. "5ebcaab2.enc" instead of "5EBCAAB2.ENC".  The latter
         should be renamed to the former. */

      if (strlen(dirent->d_name) != 12 ||
          (strcmp(dirent->d_name + 8, ".ENC") != 0 &&
           strcmp(dirent->d_name + 8, ".enc") != 0))
         continue;

      for (bad = 0, i = 0; i < 8; i++)
         if (!isxdigit((int) dirent->d_name[i])) bad = 1;
      if (bad) {
         printf("filesystem: weird file name %s, skipping\n", dirent->d_name);
         continue;
      }

      sscanf(dirent->d_name, "%lx", &id);

      if (id == 0) {
         printf("filesystem: file name %s is illegal (id 0 is reserved)\n",
            dirent->d_name);
         continue;
      }

      if (id == INFOSECTORFILE_ID) continue;

      if (!(fsi = addFile(pState, id))) return res | AEFSCK_FAIL;
      makeStorageName(pState, id, szName);
      if (stat(szName, &st)) {
         printf("filesystem: statting %s: %s\n",
            dirent->d_name, strerror(errno));
	 return res | AEFSCK_FAIL;
      }
      fsi->cbStorageSize = st.st_size;
   }

   closedir(dir);

   return res;
}


static int fsiComparator(const void * p1, const void * p2)
{
   return
      (* * (FSItem * *) p1).id - 
      (* * (FSItem * *) p2).id;
}


/* Sort the the files by ID. */
static int sortFiles(State * pState)
{
   FSItem * * fsilist, * fsi, * * fsilink;
   unsigned int i, j;

   fsilist = malloc(pState->cFiles * sizeof(FSItem *));
   if (!fsilist && pState->cFiles) {
      printf("filesystem: out of memory\n");
      return AEFSCK_FAIL;
   }

   for (i = 0, j = 0; i < FSIHASHTAB; i++)
      for (fsi = pState->fsihashtab[i]; fsi; fsi = fsi->pNextInHash)
         fsilist[j++] = fsi;
   assert(j == pState->cFiles);

   qsort(fsilist, pState->cFiles, sizeof(FSItem *), fsiComparator);

   fsilink = &pState->pFirstSorted;
   for (i = 0; i < pState->cFiles; i++) {
      *fsilink = fsilist[i];
      fsilink = &fsilist[i]->pNextSorted;
   }
   *fsilink = 0;

   free(fsilist);
      
   return 0;
}


/* Check all sectors in the file for readability.  If there are
   decryption errors, the sector is rewritten (this will probably
   destroy some or all of the data in the sector). */
static int scanFile(State * pState, FSItem * fsi)
{
   int res = 0;
   CoreResult cr;
   SectorNumber cs;

   for (cs = 0; cs < fsi->info.csSet; cs++) {

      cr = coreFetchSectors(pState->pVolume, fsi->id, cs, 1,
         pState->flags & FSCK_FIX ? CFETCH_ADD_BAD : 0);

      switch (cr) {
         case CORERC_OK:
            break;
         
         case CORERC_BAD_CHECKSUM:
            res |= AEFSCK_ERRORFOUND;
            printf("%s: checksum error in sector %ld",
               printFileName(pState, fsi->id), cs);
            if (pState->flags & FSCK_FIX) {
               printf(", rewriting (data will probably be garbled)\n");
               coreSetSectorData(pState->pVolume, fsi->id, cs, 0, 0,
                  0, 0); /* writing 0 bytes will dirty the sector */
               cr = coreFlushSector(pState->pVolume, fsi->id, cs);
               if (cr) {
                  printf("%s: unable to flush sector %ld: %s\n",
                     printFileName(pState, fsi->id), cs, core2str(cr));
                  res |= AEFSCK_ABORT;
               }
            } else printf("\n");
            break;

         default:
            printf("%s: cannot read sector %ld: %s\n",
               printFileName(pState, fsi->id), cs, core2str(cr));
            res |= AEFSCK_ERRORFOUND | AEFSCK_NOTFIXED;
      }
      
   }

   return res;
}


static void makeDefaultFileInfo(State * pState, FSItem * fsi)
{
   memset(&fsi->info, 0, sizeof(fsi->info));
   fsi->info.flFlags = CFF_IFREG | CFF_IRUSR | CFF_IWUSR;
   fsi->info.cRefs = 0;
   fsi->info.csSet = fsi->cbStorageSize / SECTOR_SIZE;
   fsi->info.cbFileSize = fsi->info.csSet * PAYLOAD_SIZE;
   fsi->info.timeCreation = fsi->info.timeAccess =
      fsi->info.timeWrite = time(0);
   fsi->info.idParent = 0;
   fsi->info.cbEAs = 0;
   fsi->info.idEAFile = 0;
}


static int createInfoSector(State * pState, FSItem * fsi)
{
   int res = 0;
   CoreResult cr;
   
   cr = coreSetFileInfo(pState->pVolume, fsi->id, &fsi->info);
   if (cr) {
      printf("isf: cannot resize: %s\n", core2str(cr));
      return res | AEFSCK_ABORT;
   }

   if (fsi->id >= pState->csISFSize) 
      pState->csISFSize = fsi->id + 1;

   pState->fRewriteFreeList = true;

   return res;
}


static int checkInfoSector(State * pState, FSItem * fsi)
{
   int res = 0;
   CoreResult cr;

   if (fsi->id >= pState->csISFSize) {
      res |= AEFSCK_ERRORFOUND;
      printf("file %08lx: info sector does not exist", fsi->id);
      makeDefaultFileInfo(pState, fsi);
      if (pState->flags & FSCK_FIX) {
         printf(", creating with default values\n");
         res |= createInfoSector(pState, fsi);
         if (STOP(res)) return res;
      } else {
          printf("\n");
          return res;
      }
   }

/*    coreFetchSectors(pState->pVolume, INFOSECTORFILE_ID, */
/*       (fsi->id / 256) * 256, 256, 0); */

   cr = coreQueryFileInfo(pState->pVolume, fsi->id, &fsi->info);
   if (cr) {
      res |= AEFSCK_ERRORFOUND;
      printf("file %08lx: cannot read info sector: %s",
         fsi->id, core2str(cr));
      makeDefaultFileInfo(pState, fsi);
      if (pState->flags & FSCK_FIX) {
         printf(", rewriting with default values\n");
         res |= createInfoSector(pState, fsi);
         if (STOP(res)) return res;
      } else printf("\n");
   }

   /* At this point, fsi->info should be initialized. */
   
   return res;
}


static int checkInfoSectors(State * pState)
{
   int res = 0;
   FSItem * fsi;

   for (fsi = pState->pFirstSorted; fsi; fsi = fsi->pNextSorted) {
      res |= checkInfoSector(pState, fsi);
      if (STOP(res)) return res;
      if (fInterrupted) return res | AEFSCK_INTERRUPT;
   }

   return res;
}


static int makeFreeList(State * pState)
{
   FSItem * fsi;
   
   pState->pFreeList = malloc(pState->csISFSize);
   if (!pState->pFreeList) return AEFSCK_FAIL;

   memset(pState->pFreeList, '?', pState->csISFSize);

   for (fsi = pState->pFirstSorted; fsi; fsi = fsi->pNextSorted)
      if (fsi->id < pState->csISFSize) 
         pState->pFreeList[fsi->id] = 'I';
      else
         /* can only happen if we're not fixing; but then we won't
            rewrite the free list anyway, so that's not a problem */
         ;
      
   return 0;
}


static int checkFreeList(State * pState)
{
   int res;
   CoreResult cr;
   CryptedFileInfoFreeLink sentinel, link;
   CryptedFileID idNextFree, id;
   SectorNumber csSize;
   
   /* Get the sentinel, which contains the head of the linked list of
      free info sectors. */
   cr = coreQuerySectorData(pState->pVolume, INFOSECTORFILE_ID, 0,
      0, sizeof(sentinel), 0, &sentinel);
   if (cr) {
      printf("isf: cannot read free list sentinel: %s\n", core2str(cr));
      return AEFSCK_ERRORFOUND;
   }
   
   if (bytesToInt32(sentinel.magic) != INFOSECTOR_MAGIC_FREE) {
      printf("isf: free list sentinel is corrupt\n");
      return AEFSCK_ERRORFOUND;
   }

   idNextFree = bytesToInt32(sentinel.idNextFree);
   
   csSize = bytesToInt32(sentinel.csSize);

   if (csSize != pState->csISFSize) {
      printf("isf: free list sentinel's csSize field does not match actual size\n");
      return AEFSCK_ERRORFOUND;
   }

   assert(pState->csISFSize); /* otherwise pState->pFreeList is too
                                 small */
   pState->pFreeList[0] = 'S';
   
   while (idNextFree) {

      if (idNextFree >= pState->csISFSize) {
         printf("isf: non-existing entry %08lx in free list\n",
            idNextFree);
         return AEFSCK_ERRORFOUND;
      }

      if (pState->pFreeList[idNextFree] == 'I') {
         printf("isf: free list entry %08lx should be an info sector\n",
            idNextFree);
         return AEFSCK_ERRORFOUND;
      }
      
      if (pState->pFreeList[idNextFree] != '?') {
         printf("isf: cycle in free list (discovered in entry %08lx)\n",
            idNextFree);
         return AEFSCK_ERRORFOUND;
      }
      
      cr = coreQuerySectorData(pState->pVolume, INFOSECTORFILE_ID,
         idNextFree, 0, sizeof(link), 0, &link);
      if (cr) {
         printf("isf: cannot read free list entry %08lx\n",
            idNextFree);
         return AEFSCK_ERRORFOUND;
      }
         
      if (bytesToInt32(link.magic) != INFOSECTOR_MAGIC_FREE) {
         printf("isf: free list entry %08lx is corrupt\n", idNextFree);
         return AEFSCK_ERRORFOUND;
      }

      pState->pFreeList[idNextFree] = 'F';
   
      idNextFree = bytesToInt32(link.idNextFree);
   }

   res = 0;
   
   for (id = 0; id < pState->csISFSize; id++)
      if (pState->pFreeList[id] == '?') {
         printf("isf: sector %08lx missing from free list\n", id);
         res |= AEFSCK_ERRORFOUND;
      }
   
   return res;
}


static int rewriteFreeList(State * pState)
{
   CoreResult cr;
   CryptedFileID idCur, idNext;
   CryptedFileInfoFreeLink link;
   
   printf("isf: rewriting free list...\n");

   idCur = 0;

   do {
      for (idNext = idCur + 1; (idNext < pState->csISFSize) &&
              (pState->pFreeList[idNext] == 'I'); idNext++) ;
      if (idNext >= pState->csISFSize) idNext = 0;
      
      int32ToBytes(INFOSECTOR_MAGIC_FREE, link.magic);
      int32ToBytes(idNext, link.idNextFree);
      int32ToBytes(idCur ? 0 : pState->csISFSize, link.csSize);

      cr = coreSetSectorData(pState->pVolume, INFOSECTORFILE_ID,
         idCur, 0, sizeof(link), CFETCH_NO_READ, &link);
      if (cr) { /* shouldn't go wrong */
         printf("isf: cannot allocate/set sector\n");
         return AEFSCK_ABORT;
      }
         
      cr = coreFlushSector(pState->pVolume, INFOSECTORFILE_ID, idCur);
      if (cr) {
         printf("isf: unable to write free list entry %08lx: %s\n",
            idCur, core2str(cr));
         return AEFSCK_ABORT;
      }

      idCur = idNext;
   } while (idCur);
   
   return 0;
}


static int checkISF(State * pState)
{
   char szISFName[MAX_VOLUME_BASE_PATH_NAME + 16];
   struct stat st;
   int res = 0, res2;
   CoreResult cr;

   makeStorageName(pState, INFOSECTORFILE_ID, szISFName);
   
   if (pState->flags & FSCK_VERBOSE)
      printf("phase: checking basic ISF integrity...\n");
   
   /* Does the ISF exist? */
retry:   
   if (stat(szISFName, &st)) {
      
      if (errno != ENOENT) {
         printf("isf: %s\n", strerror(errno));
         return res | AEFSCK_ABORT;
      }

      res |= AEFSCK_ERRORFOUND;
      
      printf("isf: does not exist");
      if (!(pState->flags & FSCK_FIX)) {
         /* Not much sense in continuing. */
         printf(", unable to proceed\n");
         return res | AEFSCK_ABORT;
      }

      /* It doesn't exists.  Recreate it. */
      printf(", recreating\n");
      cr = coreCreateFile(pState->pVolume, INFOSECTORFILE_ID, 1);
      if (cr) {
         printf("isf: cannot create: %s\n", core2str(cr));
         return res | AEFSCK_ABORT;
      }
      cr = coreInitISF(pState->pVolume);
      if (cr) {
         printf("isf: cannot init: %s\n", core2str(cr));
         return res | AEFSCK_ABORT;
      }

      goto retry;
   }

   /* Is it a regular file? */
   if (!S_ISREG(st.st_mode)) {
      res |= AEFSCK_ERRORFOUND;
      printf("isf: not a regular file, cannot continue\n");
      return res | AEFSCK_ABORT;
   }

   /* Is the storage file size a multiple of the sector size? */
   if (st.st_size % SECTOR_SIZE != 0) {
      res |= AEFSCK_ERRORFOUND;
      printf("isf: invalid size");
      if (pState->flags & FSCK_FIX) {
         printf(", truncating\n");
         cr = coreSuggestFileAllocation(pState->pVolume,
            INFOSECTORFILE_ID, st.st_size / SECTOR_SIZE);
         if (cr) {
            printf("isf: cannot truncate: %s\n", core2str(cr));
            return res | AEFSCK_ABORT;
         }
         goto retry;
      } else printf("\n");
   }

   /* The ISF header will be checked when we walk the free list. */

   pState->csISFSize = st.st_size / SECTOR_SIZE;
   pState->fRewriteFreeList = false;

   if (pState->flags & FSCK_VERBOSE)
      printf("phase: looking for storage files...\n");
   
   res |= addFiles(pState);
   if (STOP(res)) return res;

   res |= sortFiles(pState);
   if (STOP(res)) return res;

   if (pState->flags & FSCK_VERBOSE)
      printf("phase: reading info sectors...\n");
   
   res |= checkInfoSectors(pState);
   if (STOP(res)) return res;

   res |= makeFreeList(pState);
   if (STOP(res)) return res;

   if (!pState->fRewriteFreeList) { /* otherwise, don't bother */
      
      if (pState->flags & FSCK_VERBOSE)
         printf("phase: checking ISF free list...\n");
   
      res2 = checkFreeList(pState);
      res |= res2;
      if (STOP(res)) return res;
      if (res2) pState->fRewriteFreeList = true;
   }

   if (pState->fRewriteFreeList && (pState->flags & FSCK_FIX)) {
      res |= rewriteFreeList(pState);
      if (STOP(res)) return res;
   }

   free(pState->pFreeList);

   return res;
}


static int createRoot(State * pState)
{
   int res = 0;
   CoreResult cr;
   CryptedFileInfo info;
   FSItem * fsiroot;
   
   memset(&info, 0, sizeof(info));
   info.flFlags = CFF_IFDIR | 0700; /* rwx for user */
   info.cRefs = 1;
   info.cbFileSize = 0;
   info.timeWrite = info.timeAccess = info.timeCreation = time(0);
   info.idParent = 0;
   /* uid and gid are set to 0 */
   cr = coreCreateBaseFile(pState->pVolume, &info,
      &pState->pSuperBlock->idRoot);
   if (cr) {
      printf("root: cannot create: %s\n", core2str(cr));
      return res | AEFSCK_ABORT;
   }

   /* coreCreateBaseFile() has filled in the remaining fields of
      info. */

   res |= writeSuperBlock(pState->pSuperBlock);
   if (STOP(res)) return res;
   
   if (!(fsiroot = addFile(pState, pState->pSuperBlock->idRoot)))
      return res | AEFSCK_FAIL;
   fsiroot->info = info;
   fsiroot->flags |= FSI_IGNORE;

   res |= sortFiles(pState);
   if (STOP(res)) return res;

   return res;
}


static int writeFileInfo(State * pState, FSItem * fsi)
{
   CoreResult cr;
   cr = coreSetFileInfo(pState->pVolume, fsi->id, &fsi->info);
   if (cr) {
      printf("%s: cannot write file info: %s\n",
         printFileName(pState, fsi->id), core2str(cr));
      return AEFSCK_ABORT;
   }
   return 0;
}


static int checkRoot(State * pState)
{
   int res = 0;
   FSItem * fsiroot;

   if (pState->flags & FSCK_VERBOSE)
      printf("phase: checking root...\n");
   
   fsiroot = findFile(pState, pState->pSuperBlock->idRoot);

   /* Does the root exist? */
   if (!fsiroot) {
      res |= AEFSCK_ERRORFOUND;
      printf("root (file %08lx): does not exist",
         pState->pSuperBlock->idRoot);
      if (pState->flags & FSCK_FIX) {
         printf(", creating\n");
         res |= createRoot(pState);
         if (STOP(res)) return res;
         fsiroot = findFile(pState, pState->pSuperBlock->idRoot);
         assert(fsiroot);
      } else {
         printf("\n");
         return res;
      }
   }

   /* Is it a directory? */
   if (!CFF_ISDIR(fsiroot->info.flFlags)) {
      res |= AEFSCK_ERRORFOUND;
      printf("root (file %08lx): not a directory",
         pState->pSuperBlock->idRoot);
      if (pState->flags & FSCK_FIX) {
         printf(", recreating\n");
         res |= createRoot(pState);
         if (STOP(res)) return res;
         fsiroot = findFile(pState, pState->pSuperBlock->idRoot);
         assert(fsiroot);
      } else {
         printf("\n");
         return res;
      }
   }

   /* It shouldn't have a parent. */
   if (fsiroot->info.idParent) {
      res |= AEFSCK_ERRORFOUND;
      printf("root (file %08lx): has a parent",
         pState->pSuperBlock->idRoot);
      if (pState->flags & FSCK_FIX) {
         printf(", clearing idParent field\n");
         fsiroot->info.idParent = 0;
         res |= writeFileInfo(pState, fsiroot);
         if (STOP(res)) return res;
      } else printf("\n");
   }

   /* It should have a reference count of 1. */
   if (fsiroot->info.cRefs != 1) {
      res |= AEFSCK_ERRORFOUND;
      printf("root (file %08lx): reference count is incorrect (%d)",
         pState->pSuperBlock->idRoot, fsiroot->info.cRefs);
      if (pState->flags & FSCK_FIX) {
         printf(", setting to 1\n");
         fsiroot->info.cRefs = 1;
         res |= writeFileInfo(pState, fsiroot);
         if (STOP(res)) return res;
      } else printf("\n");
   }

   fsiroot->cRefs++;

   return res;
}


static void checkTime(State * pState, FSItem * fsi,
   char * what, CoreTime t)
{
   char szTime[128];
   time_t t2 = t;
   if (time(0) < t2) {
      strftime(szTime, sizeof(szTime), "%a, %d %b %Y %H:%M:%S UTC",
         gmtime(&t2));
      printf(
         "%s: warning: the %s time (%s) is in the future\n",
         printFileName(pState, fsi->id), what, szTime);
   }
}


static int changeToRegularFile(State * pState, FSItem * fsi)
{
   fsi->info.flFlags &= ~(CFF_IFMT | CFF_EXTEAS);
   fsi->info.flFlags |= CFF_IFREG;
   fsi->info.idParent = 0;
   fsi->info.cbEAs = 0;
   fsi->info.idEAFile = 0;
   return writeFileInfo(pState, fsi);
}


/* Clear the EA fields of the specified file.  If the file has
   external EAs, this will cause the EA file to become detached (not
   associated with any file) and to be moved to `/lost+found'. */
static int clearEAs(State * pState, FSItem * fsi)
{
   fsi->info.flFlags &= ~CFF_EXTEAS;
   fsi->info.cbEAs = 0;
   fsi->info.idEAFile = 0;
   return writeFileInfo(pState, fsi);
}


/* Read the extended attributes.  If an error occurs, detach the
   current EA file (if we have external EAs) and rewrite the EAs that
   could be read. */
static int checkEAs(State * pState, FSItem * fsi)
{
   int res = 0;
   CoreResult cr;
   CryptedEA * pFirstEA;

   cr = coreQueryEAs(pState->pVolume, fsi->id, &pFirstEA);
   
   if (cr) {
      
      res |= AEFSCK_ERRORFOUND;
      printf("%s: error reading EAs: %s",
         printFileName(pState, fsi->id), core2str(cr));
      
      if (pState->flags & FSCK_FIX) {
         printf(", rewriting salvaged EAs\n");

         res |= clearEAs(pState, fsi);
         if (STOP(res)) return res;
         
         cr = coreSetEAs(pState->pVolume, fsi->id, pFirstEA);
         if (cr) {
            printf("file %08lx: cannot write EAs: %s\n",
               fsi->id, core2str(cr));
            coreFreeEAs(pFirstEA);
            return res | AEFSCK_ABORT;
         }

         /* Re-read file info, because it has been changed by
            coreSetEAs(). */
         cr = coreQueryFileInfo(pState->pVolume, fsi->id, &fsi->info);
         if (cr) {
            printf("%s: cannot read file info: %s\n", 
               printFileName(pState, fsi->id), core2str(cr));
            return res | AEFSCK_ABORT;
         }
         
      } else printf("\n");
      
   }

   coreFreeEAs(pFirstEA);
   
   return res;
}


static int checkFileInfo(State * pState, FSItem * fsi)
{
   int res = 0;
   CoreResult cr;
   SectorNumber csMaxSet, csSet;

   /* Clamp csSet to the maxima, which depend on the storage file size
      and the actual file size. */
   csMaxSet = fsi->info.cbFileSize ?
      (fsi->info.cbFileSize - 1) / PAYLOAD_SIZE + 1 : 0;

   csSet = fsi->info.csSet;
   if (csSet > fsi->cbStorageSize / SECTOR_SIZE)
       csSet = fsi->cbStorageSize / SECTOR_SIZE;
   if (csSet > csMaxSet)
       csSet = csMaxSet;

   if (fsi->info.csSet != csSet) {
      res |= AEFSCK_ERRORFOUND;
      printf("%s: initialization too large (%ld), should be %ld",
         printFileName(pState, fsi->id),
         fsi->info.csSet, csSet);
      if (pState->flags & FSCK_FIX) {
         printf(", resetting\n");
         fsi->info.csSet = csSet;
         res |= writeFileInfo(pState, fsi);
         if (STOP(res)) return res;
      } else printf("\n");
   }

   assert(fsi->info.csSet * SECTOR_SIZE <= fsi->cbStorageSize);
   if (fsi->info.csSet * SECTOR_SIZE < fsi->cbStorageSize) {
      printf("%s: (not an error) storage file size is %ld, but %ld required",
         printFileName(pState, fsi->id),
         fsi->cbStorageSize, fsi->info.csSet * SECTOR_SIZE);
      if (pState->flags & FSCK_FIX) {
         printf(", truncating\n");
         cr = coreSuggestFileAllocation(pState->pVolume, fsi->id,
            fsi->info.csSet);
         if (cr) {
            printf("%s: cannot truncate: %s\n",
               printFileName(pState, fsi->id), core2str(cr));
            return res | AEFSCK_ABORT;
         }
         fsi->cbStorageSize = fsi->info.csSet * SECTOR_SIZE;
      } else printf("\n");
   }

   if (!CFF_ISDIR(fsi->info.flFlags) &&
       !CFF_ISEA(fsi->info.flFlags) &&
       fsi->info.idParent)
   {
      res |= AEFSCK_ERRORFOUND;
      printf("%s: parent set on non-{directory, EA} file",
         printFileName(pState, fsi->id));
      if (pState->flags & FSCK_FIX) {
         printf(", clearing\n");
         fsi->info.idParent = 0;
         res |= writeFileInfo(pState, fsi);
         if (STOP(res)) return res;
      } else printf("\n");
   }

   if (CFF_ISEA(fsi->info.flFlags) &&
       ((fsi->info.flFlags & CFF_EXTEAS) ||
        fsi->info.cbEAs))
   {
      res |= AEFSCK_ERRORFOUND;
      printf("%s: EA file has EAs",
         printFileName(pState, fsi->id));
      if (pState->flags & FSCK_FIX) {
         printf(", fixing\n");
         fsi->info.flFlags &= ~CFF_EXTEAS;
         fsi->info.cbEAs = 0;
         res |= writeFileInfo(pState, fsi);
         if (STOP(res)) return res;
      } else printf("\n");
   }

   if (!CFF_ISLNK(fsi->info.flFlags) &&
       !CFF_ISREG(fsi->info.flFlags) &&
       !CFF_ISDIR(fsi->info.flFlags) &&
       !CFF_ISCHR(fsi->info.flFlags) &&
       !CFF_ISBLK(fsi->info.flFlags) &&
       !CFF_ISFIFO(fsi->info.flFlags) &&
       !CFF_ISSOCK(fsi->info.flFlags) &&
       !CFF_ISEA(fsi->info.flFlags))
   {
      res |= AEFSCK_ERRORFOUND;
      printf("%s: invalid file type (%o)",
         printFileName(pState, fsi->id),
         fsi->info.flFlags & CFF_IFMT);
      if (pState->flags & FSCK_FIX) {
         printf(", changing to regular file\n");
         res |= changeToRegularFile(pState, fsi);
         if (STOP(res)) return res;
      } else printf("\n");
   }

   /* Check internal EAs here.  External EAs are checked in
      followExtEAFile(). */
   if (fsi->info.cbEAs && !(fsi->info.flFlags & CFF_EXTEAS)) {
      res |= checkEAs(pState, fsi);
      if (STOP(res)) return res;
   }
   
   /* !!! check for invalid file flags */
   
   checkTime(pState, fsi, "creation", fsi->info.timeCreation);
   checkTime(pState, fsi, "last access", fsi->info.timeAccess);
   checkTime(pState, fsi, "last write", fsi->info.timeWrite);

   return res;
}

     
static int readDirectory(State * pState, FSItem * fsi)
{
   int res = 0;
   CoreResult cr;

   /* We should check the file info before we read the directory
      file. */
   res |= checkFileInfo(pState, fsi);
   if (STOP(res)) return res;

   /* If we're doing a surface scan, we should scan the directory file
      now to recover whatever data we can prior to calling
      coreQueryDirEntries(). */
   if (pState->flags & FSCK_SURFACESCAN) {
      res |= scanFile(pState, fsi);
      if (STOP(res)) return res;
   }

   cr = coreQueryDirEntries(pState->pVolume, fsi->id,
      &fsi->pChildren);
   if (cr) {
      res |= AEFSCK_ERRORFOUND;
      printf("directory %08lx: error reading contents: %s",
         fsi->id, core2str(cr));
      if (pState->flags & FSCK_FIX) {
         printf(", will rewrite salvaged entries\n");
         fsi->flags |= FSI_REWRITEDIR;
      } else printf("\n");
   }

   return res;
}


static int readDirectories(State * pState)
{
   int res = 0;
   FSItem * fsi;

   if (pState->flags & FSCK_VERBOSE)
      printf("phase: reading directories...\n");
         
   for (fsi = pState->pFirstSorted; fsi; fsi = fsi->pNextSorted) {
      if (CFF_ISDIR(fsi->info.flFlags) && !(fsi->flags & FSI_IGNORE))
         res |= readDirectory(pState, fsi);
      if (STOP(res)) return res;
      if (fInterrupted) return res | AEFSCK_INTERRUPT;
   }

   return res;
}


/* Build a file tree.  The main point of this is to get intelligible
   error messages later on. */
static int buildTree(State * pState)
{
   int res = 0;
   FSItem * fsi, * fsi2;
   CryptedDirEntry * pEntry;

   for (fsi = pState->pFirstSorted; fsi; fsi = fsi->pNextSorted) {

      if (fsi->info.idParent)
         fsi->idParent = fsi->info.idParent;

      if (CFF_ISDIR(fsi->info.flFlags)) {
         for (pEntry = fsi->pChildren; pEntry; pEntry = pEntry->pNext)
            if (fsi2 = findFile(pState, pEntry->idFile))
               fsi2->idParent = fsi->id;
      }

      if ((CFF_ISDIR(fsi->info.flFlags) ||
           CFF_ISREG(fsi->info.flFlags)) &&
          (fsi->info.flFlags & CFF_EXTEAS) &&
          (fsi2 = findFile(pState, fsi->info.idEAFile)))
         fsi2->idParent = fsi->id;
   }

/*    for (fsi = pState->pFirstSorted; fsi; fsi = fsi->pNextSorted) */
/*       printf("%08x: %s\n", fsi->id, printFileName(pState, fsi->id)); */

   return res;
}


static int checkNonDirFiles(State * pState)
{
   int res = 0;
   FSItem * fsi;
   
   if (pState->flags & FSCK_VERBOSE)
      printf("phase: checking file info of non-directories...\n");
   
   for (fsi = pState->pFirstSorted; fsi; fsi = fsi->pNextSorted) {
      if (!CFF_ISDIR(fsi->info.flFlags)) {
         res |= checkFileInfo(pState, fsi);
         if (STOP(res)) return res;
      }
      if (STOP(res)) return res;
      if (fInterrupted) return res | AEFSCK_INTERRUPT;
   }

   if (pState->flags & FSCK_SURFACESCAN) {
      if (pState->flags & FSCK_VERBOSE)
         printf("phase: performing read test of non-directories...\n");
      for (fsi = pState->pFirstSorted; fsi; fsi = fsi->pNextSorted) {
         if (!CFF_ISDIR(fsi->info.flFlags)) {
            res |= scanFile(pState, fsi);
            if (STOP(res)) return res;
         }
         if (STOP(res)) return res;
         if (fInterrupted) return res | AEFSCK_INTERRUPT;
      }
   }

   return res;
}


static int isBadEntry(State * pState, FSItem * fsi,
   CryptedDirEntry * pEntry)
{
   unsigned char * p, * pszName =
      (unsigned char *) pEntry->pabName;
   bool fEmpty = true;
   bool fWhite = false;
   bool fBad = false;

   for (p = pszName; *p; p++) {
      fEmpty = false;
      fWhite = (*p == ' ');
      if (*p < 32 || *p == 127) fBad = true;
   }
   
   if (fEmpty)
      printf("%s: contains empty file name\n",
         printFileName(pState, fsi->id));
   else if (fWhite) /* do we want this? */
      printf("%s: file name `%s' ends in whitespace\n",
         printFileName(pState, fsi->id), pszName);
   else if (fBad)
      printf("%s: file name `%s' contains "
         "illegal characters\n",
         printFileName(pState, fsi->id), pszName);
   else return 0;
   
   return 1;
}


static int dirEntryComparator(const void * x1, const void * x2)
{
   CryptedDirEntry * p1 = * (CryptedDirEntry * *) x1;
   CryptedDirEntry * p2 = * (CryptedDirEntry * *) x2;
   return stricmp((char *) p1->pabName, (char *) p2->pabName);
}


static int checkDirEntryNamesInDir(State * pState, FSItem * fsi)
{
   int res = 0;
   CryptedDirEntry * pCur, * * ppCur, * pPrev, * pNext;
   CryptedDirEntry * * papEntries;
   unsigned int cChildren = 0, i;

   for (ppCur = &fsi->pChildren, pCur = *ppCur; pCur; ) {
      pNext = pCur->pNext;
      if (isBadEntry(pState, fsi, pCur)) {
         fsi->flags |= FSI_REWRITEDIR;
         pCur->pNext = 0;
         coreFreeDirEntries(pCur);
      } else {
         *ppCur = pCur;
         ppCur = &pCur->pNext;
         cChildren++;
      }
      pCur = pNext;
   }
   *ppCur = 0;

   papEntries = malloc(cChildren * sizeof(CryptedDirEntry *));
   if (!papEntries) {
      printf("%s: out of memory\n", printFileName(pState, fsi->id));
      return res | AEFSCK_FAIL;
   }

   for (pCur = fsi->pChildren, i = 0; pCur;
        pCur = pCur->pNext, i++)
      papEntries[i] = pCur;

   qsort(papEntries, cChildren, sizeof(CryptedDirEntry *),
      dirEntryComparator);

   fsi->pChildren = 0;
   for (pPrev = 0, i = 0; i < cChildren; i++) {
      pCur = papEntries[i];
      pCur->pNext = 0;
      if (!pPrev || dirEntryComparator(&pPrev, &pCur) != 0) {
         if (pPrev)
            pPrev->pNext = pCur;
         else
            fsi->pChildren = pCur;
         pPrev = pCur;
      } else {
         fsi->flags |= FSI_REWRITEDIR;
         printf("%s: duplicate file name `%s'\n",
            printFileName(pState, fsi->id), (char *) pCur->pabName);
         coreFreeDirEntries(pCur);
         cChildren--;
      }
   }

   free(papEntries);

   return res;
}

   
static int checkDirEntryNames(State * pState)
{
   int res = 0;
   FSItem * fsi;

   if (pState->flags & FSCK_VERBOSE)
      printf("phase: checking directory entry names...\n");
         
   for (fsi = pState->pFirstSorted; fsi; fsi = fsi->pNextSorted) {
      if (CFF_ISDIR(fsi->info.flFlags) && !(fsi->flags & FSI_IGNORE))
         res |= checkDirEntryNamesInDir(pState, fsi);
      if (STOP(res)) return res;
      if (fInterrupted) return res | AEFSCK_INTERRUPT;
   }

   return res;
}


static int followDirEntries(State * pState, FSItem * fsi)
{
   int res = 0;
   CryptedDirEntry * pCur, * * ppCur, * pNext;
   FSItem * fsic;
   bool fRemove;
   
   for (ppCur = &fsi->pChildren, pCur = *ppCur; pCur; ) {
      pNext = pCur->pNext;
      fRemove = false;
      
      fsic = findFile(pState, pCur->idFile);
      
      if (!fsic) {
         
         printf(
            "%s: entry `%s' (id %08lx) does not exist",
            printFileName(pState, fsi->id),
            (char *) pCur->pabName, pCur->idFile);
         if (pState->flags & FSCK_FIX) {
            printf(", removing from directory\n");
            fRemove = true;
         } else printf("\n");
         
      } else if (CFF_ISEA(fsic->info.flFlags)) {
            
         printf(
            "%s: entry `%s' (id %08lx) references an EA file",
            printFileName(pState, fsi->id),
            (char *) pCur->pabName, pCur->idFile);
         if (pState->flags & FSCK_FIX) {
            printf(", removing from directory\n");
            fRemove = true;
         } else printf("\n");

         /* redundant */
/*       } else if (CFF_ISDIR(fsic->info.flFlags) && fsic->cRefs) { */

/*          printf( */
/*             "%s: child directory `%s' (id %08x) is referenced " */
/*             "from multiple directories", */
/*             printFileName(pState, fsi->id), */
/*             (char *) pCur->pabName, pCur->idFile); */
/*          if (pState->flags & FSCK_FIX) { */
/*             printf(", removing from this directory\n"); */
/*             fRemove = true; */
/*          } else printf("\n"); */
         
      } else if (CFF_ISDIR(fsic->info.flFlags) &&
         (fsic->info.idParent != fsi->id)) {
         
         printf(
            "%s: child directory `%s' (id %08lx) references "
            "another parent ",
            printFileName(pState, fsi->id),
            (char *) pCur->pabName, pCur->idFile);
         printf("(%s)",
            printFileName(pState, fsic->info.idParent));
         if (pState->flags & FSCK_FIX) {
            printf(", removing from this directory\n");
            fRemove = true;
         } else printf("\n");
         
      } else fsic->cRefs++;
         
      if (fRemove) {
         res |= AEFSCK_ERRORFOUND;
         fsi->flags |= FSI_REWRITEDIR;
         pCur->pNext = 0;
         coreFreeDirEntries(pCur);
      } else {
         *ppCur = pCur;
         ppCur = &pCur->pNext;
      }
      
      pCur = pNext;
   }
   *ppCur = 0;

   return res;
}


static int followExtEAFile(State * pState, FSItem * fsi)
{
   int res = 0;
   FSItem * fsic;
   bool fRemove = false;
   
   fsic = findFile(pState, fsi->info.idEAFile);
   
   if (!fsic) {
      
      printf("%s: EA file %08lx does not exist",
         printFileName(pState, fsi->id), fsi->info.idEAFile);
      if (pState->flags & FSCK_FIX) {
         printf(", clearing EA fields\n");
         fRemove = true;
      } else printf("\n");
      
   } else if (!CFF_ISEA(fsic->info.flFlags)) {
      
      printf("%s: EA file %08lx is not actually an EA file",
         printFileName(pState, fsi->id), fsi->info.idEAFile);
      if (pState->flags & FSCK_FIX) {
         printf(", clearing EA fields\n");
         fRemove = true;
      } else printf("\n");
      
   } else if (fsic->info.idParent != fsi->id) {
      
      printf("%s: EA file %08lx references another parent ",
         printFileName(pState, fsi->id), fsi->info.idEAFile);
      printf("(%s)",
         printFileName(pState, fsic->info.idParent));
      if (pState->flags & FSCK_FIX) {
         printf(", clearing EA fields\n");
         fRemove = true;
      } else printf("\n");
      
   } else if (fsic->info.cbFileSize != fsi->info.cbEAs) {
   
      printf("%s: EA size does not match with size of EA file %08lx",
         printFileName(pState, fsi->id), fsi->info.idEAFile);
      if (pState->flags & FSCK_FIX) {
         printf(", clearing EA fields\n");
         fRemove = true;
      } else printf("\n");
      
   } else {

      /* Okay, we have a properly attached EA file, but is its
         content any good?  Check the EAs. */

      res |= checkEAs(pState, fsi);
      if (STOP(res)) return res;

      /* If the EAs are bad, checkEAs() will have detached the current
         EA file and created a new one.  In that case, the old one
         must be moved to `/lost+found' (so we shouldn't increase it's
         reference count). */ 

      if (fsi->info.idEAFile == fsic->id)
         fsic->cRefs++;
      
   }

   if (fRemove) {
      res |= AEFSCK_ERRORFOUND;
      res |= clearEAs(pState, fsi);
      if (STOP(res)) return res;
   }

   return res;
}


static int createLostFoundDir(State * pState)
{
   int res = 0;
   CoreResult cr;
   CryptedFileID id;
   CryptedFileInfo info;
   unsigned int i;
   char szName[128];
   
   memset(&info, 0, sizeof(info));
   info.flFlags = CFF_IFDIR | 0700; /* rwx for user */
   info.cRefs = 1;
   info.cbFileSize = 0;
   info.timeWrite = info.timeAccess = info.timeCreation = time(0);
   info.idParent = pState->pSuperBlock->idRoot;
   /* uid and gid are set to 0 */
   cr = coreCreateBaseFile(pState->pVolume, &info, &id);
   if (cr) {
      printf("lost+found: cannot create: %s\n", core2str(cr));
      return res | AEFSCK_ABORT;
   }

   for (i = 0; 1; i++) {
      strcpy(szName, "lost+found");
      if (i) sprintf(strchr(szName, 0), "%d", i);
      cr = coreAddEntryToDir(pState->pVolume,
         pState->pSuperBlock->idRoot,
         szName, id, 0);
      if (!cr) break;
      if (cr != CORERC_FILE_EXISTS) {
         printf("root: cannot add file `%s' to root: %s\n",
            szName, core2str(cr));
         return res | AEFSCK_ABORT;
      }
   }

   printf("lost+found: created as `/%s'\n", szName);
   
   pState->idLostFound = id;
   
   return 0;
}


static int findLostFoundDir(State * pState)
{
   int res = 0;
   CoreResult cr;
   CryptedFileID id;
   CryptedFileInfo info;
   
   if (pState->idLostFound) return res;
   
   cr = coreQueryIDFromPath(pState->pVolume,
      pState->pSuperBlock->idRoot, "lost+found", &id, 0);
   
   if (cr) {
      
      if (cr != CORERC_FILE_NOT_FOUND) {
         printf("root: cannot find lost+found: %s\n", core2str(cr));
         return res | AEFSCK_ABORT;
      }
      
   } else {

      cr = coreQueryFileInfo(pState->pVolume, id, &info);
      if (cr) {
         printf("lost+found: cannot query file info: %s\n", core2str(cr));
         return res | AEFSCK_ABORT;
      }

      if (CFF_ISDIR(info.flFlags)) {
         pState->idLostFound = id;
         return res;
      }

      /* Otherwise, `/lost+found' is not a directory and can't be
         used. */
   }

   res |= createLostFoundDir(pState);
   if (STOP(res)) return res;

   return res;
}


static int moveToLostFoundDir(State * pState, FSItem * fsi)
{
   int res = 0;
   CoreResult cr;
   unsigned int i;
   char szName[128];

   res |= findLostFoundDir(pState);
   if (STOP(res)) return res;
   
   if (!CFF_ISREG(fsi->info.flFlags) &&
       !CFF_ISDIR(fsi->info.flFlags)) {
      printf(
         "file %s: changing to regular file before "
         "adding to lost+found\n", printFileName(pState, fsi->id));
      res |= changeToRegularFile(pState, fsi);
      if (STOP(res)) return res;
   }

   for (i = 0; 1; i++) {
      
      switch (fsi->info.flFlags & CFF_IFMT) {
         case CFF_IFREG: strcpy(szName, "file"); break;
         case CFF_IFDIR: strcpy(szName, "dir"); break;
         case CFF_IFEA: strcpy(szName, "ea"); break;
         default: strcpy(szName, "unknown"); break;
      }
      sprintf(strchr(szName, 0), "_%08lx", fsi->id);
      if (i) sprintf(strchr(szName, 0), "_%d", i);

      cr = coreAddEntryToDir(pState->pVolume, pState->idLostFound,
         szName, fsi->id, 0);
      if (!cr) break;
      if (cr != CORERC_FILE_EXISTS) {
         printf("%s: cannot add to lost+found: %s\n",
            printFileName(pState, fsi->id), core2str(cr));
         return res | AEFSCK_ABORT;
      }
   }

   fsi->info.cRefs = 1;
   fsi->cRefs = 1;

   if (CFF_ISDIR(fsi->info.flFlags)) 
      fsi->info.idParent = pState->idLostFound;

   res |= writeFileInfo(pState, fsi);
   if (STOP(res)) return res;
      
   return res;
}


static int checkRefCounts(State * pState)
{
   int res = 0;
   FSItem * fsi;

   if (pState->flags & FSCK_VERBOSE)
      printf("phase: checking reference counts...\n");
         
   for (fsi = pState->pFirstSorted; fsi; fsi = fsi->pNextSorted) {
      if (CFF_ISDIR(fsi->info.flFlags) && !(fsi->flags & FSI_IGNORE))
         res |= followDirEntries(pState, fsi);
      if ((CFF_ISDIR(fsi->info.flFlags) ||
           CFF_ISREG(fsi->info.flFlags)) &&
          (fsi->info.flFlags & CFF_EXTEAS)) 
         res |= followExtEAFile(pState, fsi);
      if (STOP(res)) return res;
      if (fInterrupted) return res | AEFSCK_INTERRUPT;
   }

   for (fsi = pState->pFirstSorted; fsi; fsi = fsi->pNextSorted) {

      assert(!CFF_ISDIR(fsi->info.flFlags) || (fsi->cRefs <= 1));

      if (fsi->cRefs == 0) {

         res |= AEFSCK_ERRORFOUND;
         printf("%s: reference count is zero",
            printFileName(pState, fsi->id));
         if (pState->flags & FSCK_FIX) {
            printf(", adding to directory `/lost+found'\n");
            res |= moveToLostFoundDir(pState, fsi);
            if (STOP(res)) return res;
         } else printf("\n");
         
      } else if (fsi->cRefs != fsi->info.cRefs) {
         
         res |= AEFSCK_ERRORFOUND;
         printf("%s: stored reference count is %d, should be %d",
            printFileName(pState, fsi->id),
            fsi->info.cRefs, fsi->cRefs);
         if (pState->flags & FSCK_FIX) {
            printf(", fixing\n");
            fsi->info.cRefs = fsi->cRefs;
            res |= writeFileInfo(pState, fsi);
            if (STOP(res)) return res;
         } else printf("\n");
         
      }
      
      if (fInterrupted) return res | AEFSCK_INTERRUPT;
   }

   return res;
}


static int writeDirectory(State * pState, FSItem * fsi)
{
   int res = 0;
   CoreResult cr;

   if (!(fsi->flags & FSI_REWRITEDIR)) return res;

   cr = coreSetDirEntries(pState->pVolume, fsi->id,
      fsi->pChildren);
   if (cr) {
      printf("%s: cannot rewrite directory entries: %s\n",
         printFileName(pState, fsi->id), core2str(cr));
      return res | AEFSCK_ABORT;
   }

   fsi->flags &= ~FSI_REWRITEDIR;

   return res;
}


static int writeDirectories(State * pState)
{
   int res = 0;
   FSItem * fsi;

   if (pState->flags & FSCK_VERBOSE)
      printf("phase: rewriting modified directories...\n");
         
   for (fsi = pState->pFirstSorted; fsi; fsi = fsi->pNextSorted) {
      if (CFF_ISDIR(fsi->info.flFlags) && !(fsi->flags & FSI_IGNORE))
         res |= writeDirectory(pState, fsi);
      if (STOP(res)) return res;
      if (fInterrupted) return res | AEFSCK_INTERRUPT;
   }

   return res;
}


static int checkFiles(State * pState)
{
   unsigned int i;
   FSItem * fsi, * fsinext;
   int res = 0;
   
   for (i = 0; i < FSIHASHTAB; i++) pState->fsihashtab[i] = 0;

   res |= checkISF(pState);
   if (STOP(res)) return res;

   res |= checkRoot(pState);
   if (STOP(res)) return res;

   res |= readDirectories(pState);
   if (STOP(res)) return res;

   /* This step is only for the benefit of the user and may be
      omitted. */
   res |= buildTree(pState);
   if (STOP(res)) return res;

   res |= checkDirEntryNames(pState);
   if (STOP(res)) return res;
   
   /* readDirectories() has checked the file info for directories (and
      optionally done a surface scan).  Now do the same for all other
      files. */
   res |= checkNonDirFiles(pState);
   if (STOP(res)) return res;

   res |= checkRefCounts(pState);
   if (STOP(res)) return res;

   if (pState->flags & FSCK_FIX) {
      res |= writeDirectories(pState);
      if (STOP(res)) return res;
   }
   
   for (i = 0; i < FSIHASHTAB; i++)
      for (fsi = pState->fsihashtab[i]; fsi; fsi = fsinext) {
         fsinext = fsi->pNextInHash;
         free(fsi);
      }
   
   return res;
}


static int checkVolume(State * pState)
{
   int res = 0;

   res |= checkSuperBlock(pState);
   if (STOP(res)) return res;
   if (fInterrupted) return res | AEFSCK_INTERRUPT;

   res |= checkFiles(pState);
   if (STOP(res)) return res;
   if (fInterrupted) return res | AEFSCK_INTERRUPT;

   if (pState->pSuperBlock->flFlags & SBF_DIRTY) {
      printf("superblock: file system is dirty");
      if (pState->flags & FSCK_FIX) {
         printf(", clearing dirty flag\n");
         pState->pSuperBlock->flFlags &= ~SBF_DIRTY;
         res |= writeSuperBlock(pState->pSuperBlock);
      } else {
         printf("\n");
         /* A set dirty flag doesn't count as an error, but not
            clearing it should be reported. */
         res |= AEFSCK_NOTFIXED;
      }
   }
   
   return res;
}


static int checkFS2(int flags, char * pszBasePath, char * pszKey)
{
   State state;
   char szBasePath[1024];
   CoreResult cr;
   CryptedVolumeParms parms;
   int res;

   state.flags = flags;
   state.idLostFound = 0;
   
   /* Append a slash, if necessary. */
   assert(strlen(pszBasePath) < sizeof(szBasePath) - 1);
   strcpy(szBasePath, pszBasePath);
   if (!IS_PATH_SEPARATOR(szBasePath[strlen(szBasePath) - 1]))
      strcat(szBasePath, "/");

   coreSetDefVolumeParms(&parms);
   if (!(flags & FSCK_FIX)) parms.fReadOnly = true;
   
   cr = coreReadSuperBlock(szBasePath, pszKey, cipherTable, &parms,
      &state.pSuperBlock);
   if (!state.pSuperBlock) {
      printf("superblock: unable to read: %s\n", core2str(cr));
      return AEFSCK_ABORT;
   }
   state.pVolume = state.pSuperBlock->pVolume;
   state.readcr = cr;

   res = checkVolume(&state);

   cr = coreDropSuperBlock(state.pSuperBlock);
   if (cr) {
      printf(
         "filesystem: cannot close (error committing changes): %s\n",
         core2str(cr));
      res |= AEFSCK_ABORT;
   }

   return res;
}


static void breakHandler(int sig)
{
   fInterrupted = true;
}


static int checkFS(int flags, char * pszBasePath, char * pszKey)
{
   struct sigaction iact;
   struct sigaction oact_int;
#ifdef SIGBREAK   
   struct sigaction oact_break;
#endif   
   int res;

   iact.sa_handler = breakHandler;
   sigemptyset(&iact.sa_mask);
   iact.sa_flags = 0;
   
   sigaddset(&iact.sa_mask, SIGINT);
   sigaction(SIGINT, &iact, &oact_int);
   
#ifdef SIGBREAK   
   sigaddset(&iact.sa_mask, SIGBREAK);
   sigaction(SIGBREAK, &iact, &oact_break);
#endif   

   res = checkFS2(flags, pszBasePath, pszKey);

#ifdef SIGBREAK
   sigaction(SIGBREAK, &oact_break, 0);
#endif   
   sigaction(SIGINT, &oact_int, 0);

   return res;
}


char * pszProgramName;


static void printUsage(int status)
{
   if (status)
      fprintf(stderr,
         "\nTry `%s --help' for more information.\n",
         pszProgramName);
   else {
      printf("\
Usage: %s [OPTION]... AEFS-PATH\n\
Check and fix the AEFS file system stored in AEFS-PATH.\n\
\n\
  -f, --fix          fix errors (default is check only)\n\
      --force-fix    fix unreadable superblocks\n\
  -k, --key=KEY      use specified key, do not ask\n\
  -q, --quiet        don't show progress\n\
  -s, --scan         perform a `surface scan'\n\
      --help         display this help and exit\n\
      --version      output version information and exit\n\
\n\
If the key is not specified on the command-line, the user is asked\n\
to enter the key.\n\
\n\
Be careful when using `--force-fix': if you specify a wrong key\n\
aefsck will proceed to `fix' undecryptable sectors, replacing them\n\
with garbage; this will probably trash the file system, especially\n\
if `-s' is specified as well.  However, aefsck will ask for\n\
confirmation to proceed when it detects that the superblock cannot\n\
be decrypted.\n\
\n\
aefsck is totally non-interactive, except for asking the key or when\n\
`--force-fix' is specified.\n\
\n\
aefsck can be interrupted safely by pressing Ctrl+C or Ctrl+Break\n\
(i.e. by sending it SIGINT or SIGBREAK).\n\
\n\
The return code is the bitwise OR of the following values:\n\
 %2d: errors were found\n\
 %2d: errors were found and not fixed because `-f' was not specified\n\
 %2d: some condition, such as an undecryptable superblock or an\n\
     error that could not be fixed, prevented aefsck from checking\n\
     the entire file system\n\
 %2d: aefsck itself failed (bug, out of memory, etc.)\n\
 %2d: aefsck was interrupted by the user\n\
",
         pszProgramName,
         AEFSCK_ERRORFOUND,
         AEFSCK_NOTFIXED,
         AEFSCK_ABORT,
         AEFSCK_FAIL,
         AEFSCK_INTERRUPT);
   }
   exit(status);
}


int main(int argc, char * * argv)
{
   char * pszKey = 0, * pszBasePath;
   unsigned int flags = FSCK_VERBOSE;
   int c;
   
   struct option const options[] =
   {
      { "help", no_argument, 0, 1 },
      { "version", no_argument, 0, 2 },
      { "key", required_argument, 0, 'k' },
      { "fix", no_argument, 0, 'f' },
      { "force-fix", no_argument, 0, 3 },
      { "scan", no_argument, 0, 's' },
      { "quiet", no_argument, 0, 'q' },
      { 0, 0, 0, 0 } 
   };

   char szKey[1024];
   int res;

   sysInitPRNG();

   /* Parse the arguments. */
   
   pszProgramName = argv[0];

   while ((c = getopt_long(argc, argv, "k:fsq", options, 0)) != EOF) {
      switch (c) {
         case 0:
            break;

         case 1: /* --help */
            printUsage(0);
            break;

         case 2: /* --version */
            printf("aefsck - %s\n", AEFS_VERSION);
            exit(0);
            break;

         case 'k': /* --key */
            pszKey = optarg;
            break;

         case 'f': /* --fix */
            flags |= FSCK_FIX;
            break;

         case 3: /* --force-fix */
            flags |= FSCK_FIX | FSCK_FORCEFIX;
            break;

         case 's': /* --scan */
            flags |= FSCK_SURFACESCAN;
            break;

         case 'q': /* --quiet */
            flags &= ~FSCK_VERBOSE;
            break;

         default:
            printUsage(1);
      }
   }

   if (optind != argc - 1) {
      fprintf(stderr, "%s: missing or too many parameters\n", pszProgramName);
      printUsage(1);
   }

   pszBasePath = argv[optind++];

   /* Ask the use to enter the key, if it wasn't specified with "-k". */
   if (!pszKey) {
      pszKey = szKey;
      if (readKey("key: ", sizeof(szKey), szKey)) {
         fprintf(stderr, "%s: error reading key\n", pszProgramName);
         return 0;
      }
   }

   res = checkFS(flags, pszBasePath, pszKey);
   if ((res & AEFSCK_ERRORFOUND) & !(flags & FSCK_FIX))
      res |= AEFSCK_NOTFIXED;
   if (res & AEFSCK_INTERRUPT)
      printf("Interrupted!\n");

   memset(pszKey, 0, strlen(pszKey)); /* burn */
   
   return res;
}
