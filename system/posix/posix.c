/* posix.c -- Posix-specific low-level code.
   Copyright (C) 1999, 2000 Eelco Dolstra (edolstra@students.cs.uu.nl).

   $Id: posix.c,v 1.6 2000/12/30 00:43:45 eelco Exp $

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


static Bool lock(int h, int flFlags)
{
   struct flock fl;
   switch (flFlags & SOF_SHMASK) {
      case SOF_DENYALL: fl.l_type = F_WRLCK; break;
      case SOF_DENYWRITE: fl.l_type = F_RDLCK; break;
      case SOF_DENYNONE: return TRUE;
      default: return FALSE;
   }
   fl.l_whence = SEEK_SET;
   fl.l_start = 0;
   fl.l_len = 0; /* eof */
   fl.l_pid = 0; /* ??? */
   if (fcntl(h, F_SETLK, &fl) == -1)
      return FALSE;
   return TRUE;
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


File * sysOpenFile(char * pszName, int flFlags, Cred cred)
{
   int h;
   int f = makeUnixFlags(flFlags);
   int pmode = S_IREAD | S_IWRITE;
   File * pFile;
   struct stat st;
   int euid, egid;

   if (f == -1) return 0;

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
   if (h == -1) return 0;

#ifndef HAVE_SETFSUID
   if (cred.fEnforce) {
      /* Check that we have permission to access this file.  We have
         to do this *after* opening the file to prevent someone from
         exploiting the time window between stat() and open(). */
      if (fstat(h, &st)) {
         close(h);
         return 0;
      }
      if ((cred.uid != st.st_uid) || (cred.gid != st.st_gid)) {
         close(h);
         return 0;
      }
   }
#endif

   if (!lock(h, flFlags)) {
      close(h);
      return 0;
   }

   pFile = malloc(sizeof(File));
   if (!pFile) {
      close(h);
      return 0;
   }
   pFile->h = h;

   return pFile;
}


File * sysCreateFile(char * pszName, int flFlags,
   FilePos cbInitialSize, Cred cred)
{
   int h;
   int f = makeUnixFlags(flFlags);
   int pmode = S_IREAD | S_IWRITE;
   File * pFile;
   int euid, egid;

   if (f == -1) return 0;
   f |= O_BINARY | O_CREAT | O_EXCL;

   switch (flFlags & SOF_RWMASK) {
      case SOF_READONLY:  f |= O_RDONLY; break;
      case SOF_WRITEONLY: f |= O_WRONLY; break;
      case SOF_READWRITE: f |= O_RDWR;   break;
      default: return 0;
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
   if (h == -1) return 0;

   if (cred.fEnforce) {
#ifndef HAVE_SETFSUID
      if (fchown(h, cred.uid, cred.gid)) {
         close(h);
         return 0;
      }
#endif
      if (fchmod(h, cred.mode)) {
         close(h);
         return 0;
      }
   }

   if (!lock(h, flFlags)) {
      close(h);
      return 0;
   }

   pFile = malloc(sizeof(File));
   if (!pFile) {
      close(h);
      return 0;
   }
   pFile->h = h;

   if (!sysSetFileSize(pFile, cbInitialSize)) {
      sysCloseFile(pFile);
      return 0;
   }

   return pFile;
}


Bool sysCloseFile(File * pFile)
{
   int h = pFile->h;
   free(pFile);
   return !close(h);
}


Bool sysSetFilePos(File * pFile, FilePos ibNewPos)
{
   return lseek(pFile->h, ibNewPos, SEEK_SET) == ibNewPos;
}


Bool sysReadFromFile(File * pFile, FilePos cbLength,
   octet * pabBuffer, FilePos * pcbRead)
{
   int r;
   r = read(pFile->h, pabBuffer, cbLength);
   if (r == -1) return FALSE;
   *pcbRead = r;
   return TRUE;
}


Bool sysWriteToFile(File * pFile, FilePos cbLength,
   octet * pabBuffer, FilePos * pcbWritten)
{
   int r;
   r = write(pFile->h, pabBuffer, cbLength);
   if (r == -1) return FALSE;
   *pcbWritten = r;
   return TRUE;
}


Bool sysSetFileSize(File * pFile, FilePos cbSize)
{
#if HAVE_CHSIZE   
   return !chsize(pFile->h, cbSize);
#elif HAVE_FTRUNCATE
   return !ftruncate(pFile->h, cbSize);
#else
#error Cannot set file size!
#endif
}


Bool sysQueryFileSize(File * pFile, FilePos * pcbSize)
{
   struct stat s;
   if (fstat(pFile->h, &s) == -1) return FALSE;
   *pcbSize = s.st_size;
   return TRUE;
}


Bool sysDeleteFile(char * pszName, Bool fFastDelete, Cred cred)
{
   Bool res;
   int euid, egid;

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

   return res;
}


Bool sysFileExists(char * pszName)
{
   struct stat s;
   if (stat(pszName, &s) == -1) return FALSE;
   return S_ISREG(s.st_mode);
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
