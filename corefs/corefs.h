/* corefs.h -- Header file to the system-independent FS code.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: corefs.h,v 1.9 2001/09/23 13:30:11 eelco Exp $

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

#ifndef _COREFS_H
#define _COREFS_H

#include "sysdep.h"
#include "cipher.h"


typedef struct _CryptedVolume CryptedVolume;

typedef unsigned long CryptedFileID;
typedef unsigned long SectorNumber;
typedef unsigned long CryptedFilePos;


/*
 * Error codes
 */

typedef unsigned int CoreResult;

#define CORERC_OK                  0
#define CORERC_FILE_NOT_FOUND      1
#define CORERC_NOT_ENOUGH_MEMORY   2
#define CORERC_FILE_EXISTS         3
#define CORERC_INVALID_PARAMETER   4
#define CORERC_INVALID_NAME        5
#define CORERC_BAD_CHECKSUM        7
#define CORERC_BAD_INFOSECTOR      9
#define CORERC_NOT_DIRECTORY       10
#define CORERC_BAD_DIRECTORY       11
#define CORERC_BAD_TYPE            12
#define CORERC_BAD_EAS             13
#define CORERC_CACHE_OVERFLOW      14
#define CORERC_READ_ONLY           15
#define CORERC_ISF_CORRUPT         16
#define CORERC_ID_EXISTS           17
#define CORERC_SYS                 100 /* SYS_* added to this */
#define IS_CORERC_SYS(x) ((x) >= 100 && (x) <= 200)
CoreResult sys2core(SysResult sr);


/*
 * Sector data encryption/decryption
 */

#define SECTOR_SIZE 512
#define RANDOM_SIZE 4
#define CHECKSUM_SIZE 4
#define NONPAYLOAD_SIZE (CHECKSUM_SIZE + RANDOM_SIZE)
#define PAYLOAD_SIZE (SECTOR_SIZE - NONPAYLOAD_SIZE)

typedef struct {
      /* random and checksum constitute a 64-bit IV. */
      octet random[RANDOM_SIZE];
      octet checksum[CHECKSUM_SIZE];
      octet payload[PAYLOAD_SIZE];
} CryptedSectorData;

/* Flags for encryption/decryption. */
#define CCRYPT_USE_CBC 1


/* pSrc may be equal to pabDst. */
void coreEncryptSectorData(CryptedSectorData * pSrc,
   octet * pabDst, Key * pKey, unsigned int flFlags);

/* pabSrc must be different from pDst. */
CoreResult coreDecryptSectorData(octet * pabSrc,
   CryptedSectorData * pDst, Key * pKey, unsigned int flFlags);


/*
 * Low-level volume stuff
 */

#define MAX_VOLUME_BASE_PATH_NAME 256

typedef struct {
      unsigned int flCryptoFlags; /* CCRYPT_* */
      unsigned int flOpenFlags; /* SOF_* */
      Cred cred;
      bool fReadOnly;
      unsigned int cMaxCryptedFiles; /* > 0 */
      unsigned int cMaxOpenStorageFiles; /* > 0, <= cMaxCryptedFiles */
      unsigned int csMaxCached; /* > 0 */
      unsigned int csIOGranularity; /* > 0, <= csMaxCached */
      unsigned int csISFGrow; /* > 0 */
      void (* dirtyCallBack)(CryptedVolume * pVolume, bool fDirty);
      void * pUserData;
} CryptedVolumeParms;

typedef struct {
      unsigned int cCryptedFiles;
      unsigned int cOpenStorageFiles;
      unsigned int csInCache;
      unsigned int csDirty;
} CryptedVolumeStats;


void coreSetDefVolumeParms(CryptedVolumeParms * pParms);

CoreResult coreAccessVolume(char * pszBasePath, Key * pKey,
   CryptedVolumeParms * pParms, CryptedVolume * * ppVolume);

CoreResult coreDropVolume(CryptedVolume * pVolume);

CoreResult coreFlushVolume(CryptedVolume * pVolume);

CoreResult coreShrinkOpenStorageFiles(CryptedVolume * pVolume,
   unsigned int cFiles);

CryptedVolumeParms * coreQueryVolumeParms(CryptedVolume * pVolume);

void coreQueryVolumeStats(CryptedVolume * pVolume,
   CryptedVolumeStats * pStats);



/*
 * Low-level file stuff
 */

CoreResult coreCreateFile(CryptedVolume * pVolume,
   CryptedFileID id, SectorNumber csPreallocate);

CoreResult coreDestroyFile(CryptedVolume * pVolume, CryptedFileID id);

CoreResult coreFlushFile(CryptedVolume * pVolume, CryptedFileID id);

CoreResult coreSuggestFileAllocation(CryptedVolume * pVolume,
   CryptedFileID id, SectorNumber csAllocate);


/*
 * Sectors
 */

/* Flags for flFlags parameter of coreFetchSectors() and
   coreQuerySectorData(). */

/* CFETCH_NO_READ: do not actually read the sectors from disk, just
   create 0-filled sectors and add them to the cache. */
#define CFETCH_NO_READ        0x01

/* CFEFCH_ADD_BAD: add sectors to the cache even if they have a bad
   checksum.  CORERC_BAD_CHECKSUM will still be returned. */
#define CFETCH_ADD_BAD        0x02


CoreResult coreFetchSectors(CryptedVolume * pVolume,
   CryptedFileID id, SectorNumber sStart, SectorNumber csExtent,
   unsigned int flFlags);

CoreResult coreFlushSector(CryptedVolume * pVolume,
   CryptedFileID id, SectorNumber s);

CoreResult coreQuerySectorData(CryptedVolume * pVolume,
   CryptedFileID id, SectorNumber s, unsigned int offset,
   unsigned int bytes, unsigned int flFlags, void * pBuffer);

CoreResult coreSetSectorData(CryptedVolume * pVolume,
   CryptedFileID id, SectorNumber s, unsigned int offset,
   unsigned int bytes, unsigned int flFlags, void * pBuffer);


/*
 * Info sector management
 */


/* ID of the info sector file. */
#define INFOSECTORFILE_ID 0xffffffff


/* Sector # of the info sector for file ID within the info sector
   file. */
#define coreQueryInfoSectorNumber(pVolume, id) (id)


/* Magic values for allocated and free info sectors. */
#define INFOSECTOR_MAGIC_INUSE 0xba38ed1e
#define INFOSECTOR_MAGIC_FREE  0x17dc3b07


CoreResult coreInitISF(CryptedVolume * pVolume);

CoreResult coreAllocID(CryptedVolume * pVolume, CryptedFileID * pid);

CoreResult coreFreeID(CryptedVolume * pVolume, CryptedFileID id);


/*
 * Medium-level file stuff
 */


/* Maximum internal EA size. */
#define MAX_INTERNAL_EAS      384


/* Flags for encrypted files (CryptedFileInfo.flFlags).  These are
   equal to the Unix flags.  Most of them are meaningless to the OS/2
   FSD. */

#define CFF_EXTEAS 04000000 /* file has external EAs */

#define CFF_OS2A   02000000 /* file has been modified */
#define CFF_OS2S   01000000 /* system file */

#define CFF_IFMT   00370000
#define CFF_IFEA   00200000
#define CFF_IFSOCK 00140000
#define CFF_IFLNK  00120000
#define CFF_IFREG  00100000
#define CFF_IFBLK  00060000
#define CFF_IFDIR  00040000
#define CFF_IFCHR  00020000
#define CFF_IFIFO  00010000

#define CFF_ISUID  00004000
#define CFF_ISGID  00002000
#define CFF_ISVTX  00001000

#define CFF_ISLNK(m)      (((m) & CFF_IFMT) == CFF_IFLNK)
#define CFF_ISREG(m)      (((m) & CFF_IFMT) == CFF_IFREG)
#define CFF_ISDIR(m)      (((m) & CFF_IFMT) == CFF_IFDIR)
#define CFF_ISCHR(m)      (((m) & CFF_IFMT) == CFF_IFCHR)
#define CFF_ISBLK(m)      (((m) & CFF_IFMT) == CFF_IFBLK)
#define CFF_ISFIFO(m)     (((m) & CFF_IFMT) == CFF_IFIFO)
#define CFF_ISSOCK(m)     (((m) & CFF_IFMT) == CFF_IFSOCK)
#define CFF_ISEA(m)       (((m) & CFF_IFMT) == CFF_IFEA)

#define CFF_IRWXU 00700
#define CFF_IRUSR 00400
#define CFF_IWUSR 00200
#define CFF_IXUSR 00100

#define CFF_IRWXG 00070
#define CFF_IRGRP 00040
#define CFF_IWGRP 00020
#define CFF_IXGRP 00010

#define CFF_IRWXO 00007
#define CFF_IROTH 00004
#define CFF_IWOTH 00002
#define CFF_IXOTH 00001


/* Time type.  Number of seconds since 00:00:00 1-Jan-1970 UTC.
   Should last till 2106 or so.  0 means unknown. */
typedef uint32 CoreTime;


/* Note: fields marked as "ignored" are ignored by
   coreCreateBaseFile() in the structure passed in. */
typedef struct {
      uint32 flFlags;
      
      unsigned int cRefs; /* reference count */

      CryptedFilePos cbFileSize;
      SectorNumber csSet; /* ignored */

      CoreTime timeCreation;
      CoreTime timeAccess;
      CoreTime timeWrite;

      CryptedFileID idParent; /* directories and EA files only! */
      
      CryptedFilePos cbEAs; /* ignored */
      CryptedFileID idEAFile; /* ignored */

      uint32 uid, gid;
} CryptedFileInfo;


#pragma pack(1)

typedef struct {
      octet magic[4]; /* INFOSECTOR_MAGIC_INUSE */

      octet id[4];

      octet flFlags[4];

      octet uid[4], gid[4]; /* not implemented */
      
      octet cRefs[4]; /* reference count */

      octet cbFileSize[4];
      octet reserved1[4];
      octet obsolete1[4]; /* was csAllocated */
      octet reserved2[4];
      octet csSet[4];
      octet reserved3[4];

      octet timeCreation[4];
      octet timeAccess[4];
      octet timeWrite[4];

      octet idParent[4]; /* directories only! */

      octet cbEAs[4];
      octet idEAFile[4];
} CryptedFileInfoOnDisk;

#define FILEINFO_RESERVED 48


typedef struct {
      octet magic[4]; /* INFOSECTOR_MAGIC_FREE */
      octet idNextFree[4]; /* 0 = end of list */
      octet csSize[4]; /* only in list sentinel (sector 0) */
} CryptedFileInfoFreeLink;

#pragma pack()


CoreResult coreCreateBaseFile(CryptedVolume * pVolume,
   CryptedFileInfo * pInfo, CryptedFileID * pid);

CoreResult coreDestroyBaseFile(CryptedVolume * pVolume,
   CryptedFileID id);

CoreResult coreQueryFileInfo(CryptedVolume * pVolume,
   CryptedFileID id, CryptedFileInfo * pInfo);

CoreResult coreSetFileInfo(CryptedVolume * pVolume,
   CryptedFileID id, CryptedFileInfo * pInfo);

CoreResult coreReadFromFile(CryptedVolume * pVolume, CryptedFileID id,
   CryptedFilePos fpStart, CryptedFilePos cbLength, octet * pabBuffer,
   CryptedFilePos * pcbRead);

CoreResult coreWriteToFile(CryptedVolume * pVolume, CryptedFileID id,
   CryptedFilePos fpStart, CryptedFilePos cbLength, octet * pabBuffer,
   CryptedFilePos * pcbWritten);

CoreResult coreSetFileSize(CryptedVolume * pVolume, CryptedFileID id,
   CryptedFilePos cbFileSize);


/*
 * Directories
 */

typedef struct _CryptedDirEntry CryptedDirEntry;

struct _CryptedDirEntry {
      CryptedDirEntry * pNext;
      unsigned int cbName;
      octet * pabName; /* zero terminated (not incl. in cbName) */
      CryptedFileID idFile;
      unsigned int flFlags;
};

/* The on-disk structure of directory entries is: a flag byte, the
   file ID, the length of the file name (4 bytes), and the file name.
   The list of entries is zero-terminated.  A zero-length directory
   file denotes an empty directory. */

/* Flags for CryptedDirEntry.flFlags. */
#define CDF_NOT_EOL           1 /* on-disk only */
#define CDF_HIDDEN            2  


CoreResult coreAllocDirEntry(unsigned int cbName, octet * pabName,
   CryptedFileID idFile, unsigned int flFlags, 
   CryptedDirEntry * * ppEntry);

void coreFreeDirEntries(CryptedDirEntry * pEntries);

CoreResult coreQueryDirEntries(CryptedVolume * pVolume,
   CryptedFileID id, CryptedDirEntry * * ppEntries);

CoreResult coreSetDirEntries(CryptedVolume * pVolume,
   CryptedFileID id, CryptedDirEntry * pEntries);


/*
 * Extended attributes
 */

typedef struct _CryptedEA CryptedEA;

struct _CryptedEA {
      CryptedEA * pNext;
      char * pszName;
      unsigned int cbValue;
      octet * pabValue;
      unsigned int flFlags;
};

/* The on-disk structure of EAs is: a flag byte, the zero-terminated
   file name, the value size (4 bytes), and the value data.  The list
   of entries is zero-terminated.  A zero-length EA list denotes that
   there are no EAs. */

/* Flags for CryptedEA.flFlags. */
#define CEF_NOT_EOL           1 /* on-disk only */
#define CEF_CRITICAL          2


CoreResult coreAllocEA(char * pszName, unsigned int cbValue, 
   unsigned int flFlags, CryptedEA * * ppEA);

void coreFreeEAs(CryptedEA * pEAs);

CoreResult coreQueryEAs(CryptedVolume * pVolume,
   CryptedFileID id, CryptedEA * * ppEAs);

CoreResult coreSetEAs(CryptedVolume * pVolume,
   CryptedFileID id, CryptedEA * pEAs);


#endif /* !_COFEFS_H */
