/* os2.c -- OS/2 (EMX)-specific low-level code.
   Copyright (C) 1999, 2000 Eelco Dolstra (edolstra@students.cs.uu.nl).

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


File * sysOpenFile(char * pszName, int flFlags,
   FilePos cbInitialSize)
{
   APIRET rc;
   HFILE h;
   ULONG ulAction;
   File * pFile;
   LONG cExtra = 16;
   ULONG cCur;
   int retry = 1;

again:
   if ((rc = DosOpen((PSZ) pszName, &h, &ulAction, cbInitialSize,
      FILE_NORMAL | FILE_ARCHIVED,
      flFlags >> 16,
      (flFlags & 0xffff) | OPEN_FLAGS_FAIL_ON_ERROR |
      OPEN_FLAGS_NOINHERIT, 0)))
   {
      /* Increasing the number of handles seems to be incompatible
         with EMX.  Better use a large enough value for the `-h' EMX
         option. */
#if 0
      if (rc == ERROR_TOO_MANY_OPEN_FILES && retry) {
         fprintf(stderr, "increasing fh count\n");
         fflush(stderr);
         if (DosSetRelMaxFH(&cExtra, &cCur)) return 0;
         retry = 0;
         goto again;
      }
      fprintf(stderr, "DosOpen rc=%ld\n", rc);
      fflush(stderr);
#endif      
      return 0;
   }

   pFile = malloc(sizeof(File));
   if (!pFile) {
      DosClose(h);
      return 0;
   }
   pFile->h = h;

   return pFile;
}


Bool sysCloseFile(File * pFile)
{
   APIRET rc;
   int h = pFile->h;
   free(pFile);
   rc = DosClose(h);
   return rc == NO_ERROR;
}


Bool sysSetFilePos(File * pFile, FilePos ibNewPos)
{
   ULONG ibActual;
   return !DosSetFilePtr(pFile->h, ibNewPos, FILE_BEGIN, &ibActual);
}


Bool sysReadFromFile(File * pFile, FilePos cbLength,
   octet * pabBuffer, FilePos * pcbRead)
{
   ULONG cbActual;
   if (DosRead(pFile->h, pabBuffer, cbLength, &cbActual))
      return FALSE;
   *pcbRead = cbActual;
   return TRUE;
}


Bool sysWriteToFile(File * pFile, FilePos cbLength,
   octet * pabBuffer, FilePos * pcbWritten)
{
   ULONG cbActual;
   if (DosWrite(pFile->h, pabBuffer, cbLength, &cbActual))
      return FALSE;
   *pcbWritten = cbActual;
   return TRUE;
}


Bool sysSetFileSize(File * pFile, FilePos cbSize)
{
   return !DosSetFileSize(pFile->h, cbSize);
}


Bool sysQueryFileSize(File * pFile, FilePos * pcbSize)
{
   FILESTATUS3 info;
   if (DosQueryFileInfo(pFile->h, FIL_STANDARD, &info, sizeof(info)))
      return FALSE;
   *pcbSize = info.cbFile;
   return TRUE;
}


Bool sysDeleteFile(char * pszName, Bool fFastDelete)
{
   return fFastDelete
      ? !DosForceDelete((PSZ) pszName)
      : !DosDelete((PSZ) pszName);
}


Bool sysFileExists(char * pszName)
{
   FILESTATUS3 info;
   if (DosQueryPathInfo((PSZ) pszName,
      FIL_STANDARD, &info, sizeof(info)))
      return FALSE;
   return !(info.attrFile & FILE_DIRECTORY);
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
