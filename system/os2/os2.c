/* os2.c -- OS/2 (EMX)-specific low-level code.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: os2.c,v 1.7 2001/09/23 13:30:21 eelco Exp $

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
#include <time.h>
#include <assert.h>
#define INCL_DOSERRORS
#include <os2.h>

#include "sysdep.h"


struct _File {
      HFILE h;
};


static SysResult os2sys(APIRET rc)
{
   switch (rc) {
      case NO_ERROR: return SYS_OK;
      case ERROR_FILE_NOT_FOUND:
      case ERROR_PATH_NOT_FOUND:
      case ERROR_OPEN_FAILED:
         return SYS_FILE_NOT_FOUND;
      case ERROR_ACCESS_DENIED: return SYS_ACCESS_DENIED;
      case ERROR_NOT_ENOUGH_MEMORY: return SYS_NOT_ENOUGH_MEMORY;
      case ERROR_WRITE_PROTECT: return SYS_ROFS;
      case ERROR_NOT_READY:
      case ERROR_CRC:
      case ERROR_SECTOR_NOT_FOUND:
      case ERROR_WRITE_FAULT:
      case ERROR_READ_FAULT:
      case ERROR_GEN_FAILURE:
      case ERROR_HANDLE_DISK_FULL:
      case ERROR_DISK_FULL:
         return SYS_IO;
      case ERROR_SHARING_VIOLATION:
      case ERROR_LOCK_VIOLATION:
         return SYS_LOCKED;
      default: return SYS_UNKNOWN;
   }
}


static ULONG makeOS2Flags(int flFlags)
{
   ULONG f = 0;
   
   switch (flFlags & SOF_RWMASK) {
      case SOF_READONLY:  f |= OPEN_ACCESS_READONLY;  break;
      case SOF_WRITEONLY: f |= OPEN_ACCESS_WRITEONLY; break;
      case SOF_READWRITE: f |= OPEN_ACCESS_READWRITE; break;
      default: return 0;
   }

   switch (flFlags & SOF_SHMASK) {
      case SOF_DENYALL:   f |= OPEN_SHARE_DENYREADWRITE; break;
      case SOF_DENYWRITE: f |= OPEN_SHARE_DENYWRITE; break;
      case SOF_DENYNONE:  f |= OPEN_SHARE_DENYNONE; break;
      default: return 0;
   }

   switch (flFlags & SOF_LCMASK) {
      case SOF_NO_LOCALITY:      f |= OPEN_FLAGS_NO_LOCALITY; break;
      case SOF_SEQUENTIAL:       f |= OPEN_FLAGS_SEQUENTIAL; break;
      case SOF_RANDOM:           f |= OPEN_FLAGS_RANDOM; break;
      case SOF_RANDOMSEQUENTIAL: f |= OPEN_FLAGS_RANDOMSEQUENTIAL; break;
      default: return 0;
   }

   if (flFlags & SOF_NO_CACHE)      f |= OPEN_FLAGS_NO_CACHE;
   if (flFlags & SOF_WRITE_THROUGH) f |= OPEN_FLAGS_WRITE_THROUGH;

   return f;
}


SysResult sysOpenFile(char * pszName, int flFlags, Cred cred, 
    File * * ppFile)
{
   APIRET rc;
   HFILE h;
   ULONG ulAction;
   File * pFile;
   ULONG f = makeOS2Flags(flFlags), g = 0;
   *ppFile = 0;
   if (!f) return 0;
   
   if (flFlags & SOF_TRUNC_IF_EXISTS)
      g |= OPEN_ACTION_REPLACE_IF_EXISTS;
   else
      g |= OPEN_ACTION_OPEN_IF_EXISTS;
   if (flFlags & SOF_CREATE_IF_NEW)
      g |= OPEN_ACTION_CREATE_IF_NEW;
   else
      g |= OPEN_ACTION_FAIL_IF_NEW;

   if ((rc = DosOpen((PSZ) pszName, &h, &ulAction, 0,
      FILE_NORMAL | FILE_ARCHIVED,
      g, f | OPEN_FLAGS_FAIL_ON_ERROR | OPEN_FLAGS_NOINHERIT, 0)))
      return os2sys(rc);
   
   pFile = malloc(sizeof(File));
   if (!pFile) {
      DosClose(h);
      return SYS_NOT_ENOUGH_MEMORY;
   }
   pFile->h = h;

   *ppFile = pFile;
   return SYS_OK;
}


SysResult sysCreateFile(char * pszName, int flFlags, 
    FilePos cbInitialSize, Cred cred, File * * ppFile)
{
   APIRET rc;
   HFILE h;
   ULONG ulAction;
   File * pFile;
   ULONG f = makeOS2Flags(flFlags);
   *ppFile = 0;
   if (!f) return 0;
   
   if ((rc = DosOpen((PSZ) pszName, &h, &ulAction, cbInitialSize,
      FILE_NORMAL | FILE_ARCHIVED,
      OPEN_ACTION_CREATE_IF_NEW | OPEN_ACTION_FAIL_IF_EXISTS,
      f | OPEN_FLAGS_FAIL_ON_ERROR | OPEN_FLAGS_NOINHERIT, 0)))
      return os2sys(rc);
   
   pFile = malloc(sizeof(File));
   if (!pFile) {
      DosClose(h);
      return SYS_NOT_ENOUGH_MEMORY;
   }
   pFile->h = h;

   *ppFile = pFile;
   return SYS_OK;
}


SysResult sysCloseFile(File * pFile)
{
   int h = pFile->h;
   free(pFile);
   return os2sys(DosClose(h));
}


SysResult sysSetFilePos(File * pFile, FilePos ibNewPos)
{
   ULONG ibActual;
   return os2sys(DosSetFilePtr(pFile->h, ibNewPos, FILE_BEGIN, &ibActual));
}


SysResult sysReadFromFile(File * pFile, FilePos cbLength,
   octet * pabBuffer, FilePos * pcbRead)
{
   APIRET rc;
   ULONG cbActual;
   if (rc = DosRead(pFile->h, pabBuffer, cbLength, &cbActual))
      return os2sys(rc);
   *pcbRead = cbActual;
   return SYS_OK;
}


SysResult sysWriteToFile(File * pFile, FilePos cbLength,
   octet * pabBuffer, FilePos * pcbWritten)
{
   APIRET rc;
   ULONG cbActual;
   if (rc = DosWrite(pFile->h, pabBuffer, cbLength, &cbActual))
      return os2sys(rc);
   *pcbWritten = cbActual;
   return SYS_OK;
}


SysResult sysSetFileSize(File * pFile, FilePos cbSize)
{
   return os2sys(DosSetFileSize(pFile->h, cbSize));
}


SysResult sysQueryFileSize(File * pFile, FilePos * pcbSize)
{
   APIRET rc;
   FILESTATUS3 info;
   if (rc = DosQueryFileInfo(pFile->h, FIL_STANDARD, &info, sizeof(info)))
      return os2sys(rc);
   *pcbSize = info.cbFile;
   return SYS_OK;
}


SysResult sysDeleteFile(char * pszName, bool fFastDelete, Cred cred)
{
   return fFastDelete
      ? os2sys(DosForceDelete((PSZ) pszName))
      : os2sys(DosDelete((PSZ) pszName));
}


SysResult sysFileExists(char * pszName, bool * pfExists)
{
   APIRET rc;
   FILESTATUS3 info;
   if (rc = DosQueryPathInfo((PSZ) pszName,
      FIL_STANDARD, &info, sizeof(info)))
   {
      if (rc != ERROR_FILE_NOT_FOUND && rc != ERROR_PATH_NOT_FOUND)
         return os2sys(rc);
      *pfExists = false;
   } else
      *pfExists = !(info.attrFile & FILE_DIRECTORY);
   return SYS_OK;
}


int cbSecureAlloced; 
int cbSecureFreed;
int cSecureAlloced;
int cSecureFreed;


void * sysAllocSecureMem(int cbSize)
{
   /* not thread safe! */
   cbSecureAlloced += cbSize;
   cSecureAlloced++;
   return malloc(cbSize);
}


static void wipe(uint32 * p, int cb)
{
   while (cb >= 4) {
#if 0 
      *p++ = 0xefbeadde; /* i.e. deadbeef */
#endif
      *p++ = 0x4c303046; /* i.e. "f00l" */
      cb -= 4;
   }
   if (cb) memset(p, 0, cb);
}


void sysFreeSecureMem(void * pMem)
{
   int cbSize = _msize(pMem);
   wipe((uint32 *) pMem, cbSize); /* burn */
   /* not thread safe! */
   cbSecureFreed += cbSize;
   cSecureFreed++;
   free(pMem);
}


void sysLockMem()
{
   fprintf(stderr, "locking is NOT available!\n");
}


/* The following PRNG (BSD) is not very good, cryptographically, but
   then we don't really need cryptographically strong PRNs yet.  */


static int prng_init = 0;


void sysInitPRNG()
{
   if (!prng_init) {
      srandom(time(0));
      prng_init = 1;
   }
}


void sysGetRandomBits(int bits, octet * dst)
{
   assert(prng_init);
   while (bits > 0) {
      *dst = (octet) random();
      bits -= 8;
      dst++;
   }
}
