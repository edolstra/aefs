/* aefsdmn.h -- Header file for the daemon code.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: aefsdmn.h,v 1.7 2001/09/23 13:30:13 eelco Exp $

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

#ifndef _AEFSDMN_H
#define _AEFSDMN_H

#define INCL_DOSERRORS
#include <os2.h>

#include <syslog.h>

#include "stubfsd.h"

#include "aefsdint.h"

#include "corefs.h"
#include "coreutils.h"
#include "superblock.h"


typedef struct _ServerData ServerData;
typedef struct _VolData VolData;

struct _ServerData{
      bool fQuit;
      
      /* Mutex semaphore guarding against concurrent access. */
      HMTX hmtxGlobal;
      
      /* Exchange buffers. */
      PFSREQUEST pRequest;
      PFSDATA pData;

      /* List of attached volumes (index 0 = drive A, etc.). */
      VolData * paVolumes[26];
      
      /* Lazy writer thread ID and termination event semaphores. */
      TID tidLazyWriter;
      HEV hevLazyWriterDie;

      /* Default values for newly attached volumes.  These can be
         changed at startup or through aefsparm.  They cannot
         be changed for attached volumes. */
      int cMaxCryptedFiles;
      int cMaxOpenStorageFiles; /* not too high! */
      int csMaxCached;
      
      /* If set, maintain the last-access time stamp of files lazily,
         that is, update it there are other changes to the file. */
      bool fLazyLastAccess;

      /* If not set, flush all volumes after processing a request in
         the runDaemon() loop.  If set, flushing is done at fixed time
         intervals by the lazy writer thread. */
      bool fLazyWrite;
};

typedef struct {
      CHAR szName[CCHMAXPATH];
      ULONG flAttr;
      CryptedDirEntry * pFirstInDir;
      CryptedDirEntry dot, dotDot;
      CryptedDirEntry * pFirst;
      CryptedDirEntry * pNext;
      int iNext;
} SearchData;

typedef struct {
      CryptedFileID idFile;
      /* Directory through which idFile was opened. */
      CryptedFileID idDir;
} OpenFileData;

struct _VolData {
      ServerData * pServerData;
      
      SuperBlock * pSuperBlock;

      char chDrive;
      
      CryptedVolume * pVolume; /* copy of pSuperBlock->pVolume */
      CryptedFileID idRoot; /* copy of pSuperBlock->idRoot */

      bool fReadOnly;

      /* Statistics. */
      int cOpenFiles;
      int cSearches;
};


/* Message severity codes. */
#define L_FATAL  LOG_ALERT
#define L_EVIL   LOG_CRIT
#define L_ERR    LOG_ERR
#define L_WARN   LOG_WARNING
#define L_INFO   LOG_INFO
#define L_DBG    LOG_DEBUG


/* Additional value for DOS attribute fields. */
#define FILE_NON83 0x40


/* Flush values for stampFileAndFlush(). */
#define SFAF_NOFLUSH    0 /* don't flush anything */
#define SFAF_FLUSHINFO  1 /* flush the info sector */
#define SFAF_FLUSHALL   2 /* flush all the file's sectors */


/* Global functions. */

void logMsg(int level, char * pszMsg, ...);

int processArgs(ServerData * pServerData, int argc, char * * argv,
   int startup);

int verifyString(char * pszStr, int cbMaxLen);

#define VERIFYFIXED(str) verifyString(str, sizeof(str))

int verifyPathName(char * pszName);

bool hasNon83Name(char * pszName);

APIRET coreResultToOS2(CoreResult cr);

void splitPath(char * pszFull, char * pszPrefix, char * pszLast);

void logsffsi(struct sffsi * psffsi);

void coreToSffsi(bool fHidden, CryptedFileInfo * pInfo,
   struct sffsi * psffsi);

USHORT makeDOSAttr(bool fHidden, CryptedFileInfo * pInfo);

void extractDOSAttr(USHORT fsAttr, CryptedFileInfo * pInfo);

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
   int iNext);

APIRET stampFileAndFlush(VolData * pVolData, CryptedFileID idFile,
   struct sffsi * psffsi, int flush);

APIRET deleteFile(VolData * pVolData, char * pszFullName);

int compareEANames(char * pszName1, char * pszName2);

APIRET addEAs(CryptedVolume * pVolume, CryptedFileID idFile,
   PFEALIST pfeas);

APIRET storeEAsInFEAList(CryptedVolume * pVolume,
   CryptedFileID idFile, CryptedFileInfo * pinfo,
   PGEALIST pgeas, ULONG cbData, char * pData);

CoreTime curTime();

int coreTimeToOS2(CoreTime time, FDATE * pfdate, FTIME * pftime);

int os2TimeToCore(FDATE fdate, FTIME ftime, CoreTime * ptime);

APIRET commitVolume(VolData * pVolData);

void dropVolume(ServerData * pServerData, VolData * pVolData);
     
void freeSearchData(SearchData * pSearchData);

CoreResult findFromCurDir(VolData * pVolData, char * szPath,
   struct cdfsi * pcdfsi, CDFSD * pcdfsd, USHORT iCurDirEnd,
   CryptedFileID * pidDir, CryptedFileID * pidFile,
   CryptedDirEntry * * ppDirEntry, char * szName);

CoreResult findFromCurDir2(VolData * pVolData, char * szPath,
   struct cdfsi * pcdfsi, CDFSD * pcdfsd, USHORT iCurDirEnd,
   CryptedFileID * pidFile, CryptedDirEntry * * ppDirEntry);
     
#define GET_VOLUME(p) \
   pVolData = pServerData->paVolumes[p->vpfsd.data[0]]; \
   if (!pVolData) return ERROR_INVALID_DRIVE; /* !!! log */


/* FSD functions. */
APIRET fsFsCtl(ServerData * pServerData, struct fsctl * pfsctl);
APIRET fsAttach(ServerData * pServerData, struct attach * pattach);
APIRET fsIOCtl(ServerData * pServerData, struct ioctl * pioctl);
APIRET fsFsInfo(ServerData * pServerData, struct fsinfo * pfsinfo);
APIRET fsFlushBuf(ServerData * pServerData,
   struct flushbuf * pflushbuf);
APIRET fsShutdown(ServerData * pServerData,
   struct shutdown * pshutdown);
APIRET fsOpenCreate(ServerData * pServerData,
   struct opencreate * popencreate);
APIRET fsClose(ServerData * pServerData, struct close * pclose);
APIRET fsRead(ServerData * pServerData, struct read * pread);
APIRET fsWrite(ServerData * pServerData, struct write * pwrite);
APIRET fsChgFilePtr(ServerData * pServerData,
   struct chgfileptr * pchgfileptr);
APIRET fsNewSize(ServerData * pServerData, struct newsize * pnewsize);
APIRET fsFileAttribute(ServerData * pServerData,
   struct fileattribute * pfileattribute);
APIRET fsFileInfo(ServerData * pServerData,
   struct fileinfo * pfileinfo);
APIRET fsCommit(ServerData * pServerData, struct commit * pcommit);
APIRET fsPathInfo(ServerData * pServerData,
   struct pathinfo * ppathinfo);
APIRET fsDelete(ServerData * pServerData, struct delete * pdelete);
APIRET fsMove(ServerData * pServerData, struct move * pmove);
APIRET fsChDir(ServerData * pServerData, struct chdir * pchdir);
APIRET fsMkDir(ServerData * pServerData, struct mkdir * pmkdir);
APIRET fsRmDir(ServerData * pServerData, struct rmdir * prmdir);
APIRET fsFindFirst(ServerData * pServerData,
   struct findfirst * pfindfirst);
APIRET fsFindNext(ServerData * pServerData,
   struct findnext * pfindnext);
APIRET fsFindFromName(ServerData * pServerData,
   struct findfromname * pfindfromname);
APIRET fsFindClose(ServerData * pServerData,
   struct findclose * pfindclose);
APIRET fsProcessName(ServerData * pServerData,
   struct processname * pprocessname);

#endif /* !_AEFSDMN_H */
