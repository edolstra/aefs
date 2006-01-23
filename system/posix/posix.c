/* posix.c -- Posix-specific low-level code.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id$

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

#include "sysdep.h"

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_SETFSUID
#include <sys/fsuid.h>
#endif
#ifdef HAVE_MLOCKALL
#include <sys/mman.h>
#endif


#ifndef O_BINARY
#define O_BINARY 0
#endif
#ifndef O_SYNC
#define O_SYNC 0
#endif


struct _File {
      int h;
};


static SysResult unix2sys()
{
   switch (errno) {
      case EPERM: return SYS_ACCESS_DENIED;
      case ENOENT: return SYS_FILE_NOT_FOUND;
      case EIO: return SYS_IO;
      case ENOMEM: return SYS_NOT_ENOUGH_MEMORY;
      case EACCES: return SYS_ACCESS_DENIED;
      case EEXIST: return SYS_FILE_EXISTS;
      case EINVAL: return SYS_INVALID_PARAMETER;
      case EROFS: return SYS_ROFS;
      default: return SYS_UNKNOWN;
   }
}


static SysResult lock(int h, int flFlags)
{
   struct flock fl;
   switch (flFlags & SOF_SHMASK) {
      case SOF_DENYALL: fl.l_type = F_WRLCK; break;
      case SOF_DENYWRITE: fl.l_type = F_RDLCK; break;
      case SOF_DENYNONE: return SYS_OK;
      default: return SYS_INVALID_PARAMETER;
   }
   fl.l_whence = SEEK_SET;
   fl.l_start = 0;
   fl.l_len = 0; /* eof */
   fl.l_pid = 0; /* ??? */
   if (fcntl(h, F_SETLK, &fl) == -1) {
      if (errno == EAGAIN) return SYS_LOCKED;
      return unix2sys();
   }
   return SYS_OK;
}


static int makeUnixFlags(int flFlags)
{
   int f = O_BINARY;

   switch (flFlags & SOF_RWMASK) {
      case SOF_READONLY:  f |= O_RDONLY; break;
      case SOF_WRITEONLY: f |= O_WRONLY; break;
      case SOF_READWRITE: f |= O_RDWR;   break;
      default: return -1;
   }
   
   if (flFlags & SOF_WRITE_THROUGH) f |= O_SYNC;

   return f;
}


#ifndef HAVE_SETFSUID
static int canAccess(uid_t uid, gid_t gid, Cred cred)
{
    if (cred.uid == 0) return 1;
    return cred.uid == uid; /* !!! weak */
}
#endif


SysResult sysOpenFile(char * pszName, int flFlags, Cred cred, 
    File * * ppFile)
{
   int h;
   int f = makeUnixFlags(flFlags);
   int pmode = S_IREAD | S_IWRITE;
   File * pFile;
   int euid = 0, egid = 0;
   SysResult sr;

   *ppFile = 0;

   if (f == -1) return SYS_INVALID_PARAMETER;

   if (flFlags & SOF_TRUNC_IF_EXISTS) f |= O_TRUNC;
   if (flFlags & SOF_CREATE_IF_NEW) f |= O_CREAT;
   
#ifdef HAVE_SETFSUID
   if (cred.fEnforce) {
      euid = geteuid(); egid = getegid();
      setfsuid(cred.uid); setfsgid(cred.gid);
   }
#endif

   h = open(pszName, f, pmode);
#ifdef HAVE_SETFSUID
   if (cred.fEnforce) {
      setfsuid(euid); setfsgid(egid);
   }
#endif
   if (h == -1) return unix2sys();

#ifndef HAVE_SETFSUID
   if (cred.fEnforce) {
      /* Check that we have permission to access this file.  We have
         to do this *after* opening the file to prevent someone from
         exploiting the time window between stat() and open(). */
      struct stat st;
      if (fstat(h, &st)) {
         close(h);
         return unix2sys();
      }
      if (!canAccess(st.st_uid, st.st_gid, cred)) {
         close(h);
         return SYS_ACCESS_DENIED;
      }
   }
#endif

   if (sr = lock(h, flFlags)) {
      close(h);
      return sr;
   }

   pFile = malloc(sizeof(File));
   if (!pFile) {
      close(h);
      return SYS_NOT_ENOUGH_MEMORY;
   }
   pFile->h = h;

   *ppFile = pFile;
   return SYS_OK;
}


SysResult sysCreateFile(char * pszName, int flFlags, 
    FilePos cbInitialSize, Cred cred, File * * ppFile)
{
   int h;
   int f = makeUnixFlags(flFlags);
   int pmode = S_IREAD | S_IWRITE;
   File * pFile;
   int euid = 0, egid = 0;
   SysResult sr;

   *ppFile = 0;

   if (f == -1) return SYS_INVALID_PARAMETER;
   f |= O_BINARY | O_CREAT | O_EXCL;

   switch (flFlags & SOF_RWMASK) {
      case SOF_READONLY:  f |= O_RDONLY; break;
      case SOF_WRITEONLY: f |= O_WRONLY; break;
      case SOF_READWRITE: f |= O_RDWR;   break;
      default: return SYS_INVALID_PARAMETER;
   }
   
   if (flFlags & SOF_WRITE_THROUGH) f |= O_SYNC;

#ifdef HAVE_SETFSUID
   if (cred.fEnforce) {
      euid = geteuid(); egid = getegid();
      setfsuid(cred.uid); setfsgid(cred.gid);
   }
#endif

   if (cred.fEnforce) umask(0077);

   h = open(pszName, f, pmode);
#ifdef HAVE_SETFSUID
   if (cred.fEnforce) {
      setfsuid(euid); setfsgid(egid);
   }
#endif
   if (h == -1) return unix2sys();

   if (cred.fEnforce) {
#ifndef HAVE_SETFSUID
      if (fchown(h, cred.uid, cred.gid)) {
         close(h);
         return unix2sys();
      }
#endif
      if (fchmod(h, cred.mode)) {
         close(h);
         return unix2sys();
      }
   }

   if (sr = lock(h, flFlags)) {
      close(h);
      return sr;
   }

   pFile = malloc(sizeof(File));
   if (!pFile) {
      close(h);
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
   if (close(h) == -1) return unix2sys();
   return SYS_OK;
}


SysResult sysSetFilePos(File * pFile, FilePos ibNewPos)
{
   if (lseek(pFile->h, ibNewPos, SEEK_SET) != ibNewPos)
      return unix2sys();
   return SYS_OK;
}


SysResult sysReadFromFile(File * pFile, FilePos cbLength,
   octet * pabBuffer, FilePos * pcbRead)
{
   int r;
   *pcbRead = 0;
   while (cbLength) {
      r = read(pFile->h, pabBuffer, cbLength);
      if (r == -1 && errno != EINTR) return unix2sys();
      if (r == 0) break;
      pabBuffer += r;
      cbLength -= r;
      *pcbRead += r;
   }
   return SYS_OK;
}


SysResult sysWriteToFile(File * pFile, FilePos cbLength,
   octet * pabBuffer, FilePos * pcbWritten)
{
   int r;
   *pcbWritten = 0;
   while (cbLength) {
      r = write(pFile->h, pabBuffer, cbLength);
      if (r == -1 && errno != EINTR) return unix2sys();
      pabBuffer += r;
      cbLength -= r;
      *pcbWritten += r;
   }
   return SYS_OK;
}


SysResult sysSetFileSize(File * pFile, FilePos cbSize)
{
   struct stat s;
   if (fstat(pFile->h, &s) == -1) return unix2sys();
   if (cbSize >= s.st_size) return SYS_OK; /* don't grow files */
   if (ftruncate(pFile->h, cbSize) == -1) return unix2sys();
   return SYS_OK;
}


SysResult sysQueryFileSize(File * pFile, FilePos * pcbSize)
{
   struct stat s;
   if (fstat(pFile->h, &s) == -1) return unix2sys();
   *pcbSize = s.st_size;
   return SYS_OK;
}


SysResult sysDeleteFile(char * pszName, bool fFastDelete, Cred cred)
{
   bool res;
   int euid = 0, egid = 0;

#ifdef HAVE_SETFSUID
   if (cred.fEnforce) {
      euid = geteuid(); egid = getegid();
      setfsuid(cred.uid); setfsgid(cred.gid);
   }
#endif

   res = remove(pszName) != -1;

#ifdef HAVE_SETFSUID
   if (cred.fEnforce) {
      setfsuid(euid); setfsgid(egid);
   }
#endif

   return res == -1 ? unix2sys() : SYS_OK;
}


SysResult sysFileExists(char * pszName, bool * pfExists)
{
   struct stat s;
   if (stat(pszName, &s) == -1) {
      if (errno != ENOENT) return unix2sys();
      *pfExists = false;
   } else 
      *pfExists = S_ISREG(s.st_mode) != 0;
   return SYS_OK;
}


void * sysAllocSecureMem(int cbSize)
{
   /* !!! Use mlock if available? */
   return malloc(cbSize);
}


void sysFreeSecureMem(void * pMem)
{
   free(pMem);
}


void sysLockMem()
{
#ifdef HAVE_MLOCKALL
   if (mlockall(MCL_FUTURE) == -1) {
      fprintf(stderr, "cannot lock memory!\n");
   }
#else
   fprintf(stderr, "locking is NOT available!\n");
#endif
}


/* We use the standard C PRNG, so it's very bad. */


static int prng_init = 0;


void sysInitPRNG()
{
   if (!prng_init) {
      srand(time(0));
      prng_init = 1;
   }
}


void sysGetRandomBits(int bits, octet * dst)
{
   assert(prng_init);
   while (bits > 0) {
      *dst = (octet) rand();
      bits -= 8;
      dst++;
   }
}
