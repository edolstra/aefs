#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "sysdep.h"


#ifndef O_BINARY
#define O_BINARY 0
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


File * sysOpenFile(char * pszName, int flFlags, Cred cred)
{
   int h;
   int f = O_BINARY;
   int pmode = S_IREAD | S_IWRITE;
   File * pFile;
   struct stat st;

   if (flFlags & SOF_TRUNC_IF_EXISTS) f |= O_TRUNC;
   if (flFlags & SOF_CREATE_IF_NEW) f |= O_CREAT;
   
   switch (flFlags & SOF_RWMASK) {
      case SOF_READONLY:  f |= O_RDONLY; break;
      case SOF_WRITEONLY: f |= O_WRONLY; break;
      case SOF_READWRITE: f |= O_RDWR;   break;
      default: return 0;
   }
   
   if (flFlags & SOF_WRITE_THROUGH) f |= O_SYNC;

   h = open(pszName, f, pmode);
   if (h == -1) return 0;

   /* Check that we have permission to access this file.  We have to
      do this *after* opening the file to prevent someone from
      exploiting the time window between stat() and open(). */
   if (cred.fEnforce) {
      if (fstat(h, &st)) {
         close(h);
         return 0;
      }
      if ((cred.uid != st.st_uid) || (cred.gid != st.st_gid)) {
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

   return pFile;
}


File * sysCreateFile(char * pszName, int flFlags,
   FilePos cbInitialSize, Cred cred)
{
   int h;
   int f = O_BINARY | O_CREAT | O_EXCL;
   int pmode = S_IREAD | S_IWRITE;
   File * pFile;

   switch (flFlags & SOF_RWMASK) {
      case SOF_READONLY:  f |= O_RDONLY; break;
      case SOF_WRITEONLY: f |= O_WRONLY; break;
      case SOF_READWRITE: f |= O_RDWR;   break;
      default: return 0;
   }
   
   if (flFlags & SOF_WRITE_THROUGH) f |= O_SYNC;

   if (cred.fEnforce) umask(0077);

   h = open(pszName, f, pmode);
   if (h == -1) return 0;

   if (cred.fEnforce) {
      if (fchown(h, cred.uid, cred.gid)) {
         close(h);
         return 0;
      }
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
   /* !!! check permissions */
   return !remove(pszName);
}


Bool sysFileExists(char * pszName)
{
   struct stat s;
   if (stat(pszName, &s) == -1) return FALSE;
   return S_ISREG(s.st_mode);
}


void * sysAllocSecureMem(int cbSize)
{
   return malloc(cbSize);
}


void sysFreeSecureMem(void * pMem)
{
   free(pMem);
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
