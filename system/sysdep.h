/* sysdep.h -- Interface to system-dependent stuff needed by the
   system-independent FS code.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: sysdep.h,v 1.11 2001/09/23 13:30:19 eelco Exp $

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

#ifndef _SYSDEP_H
#define _SYSDEP_H

#include "config.h"
#include "types.h"
#include "sysspec.h"


typedef struct _File File;
typedef unsigned long FilePos;
typedef unsigned int SysResult;


/* Error codes for sys*(). */
#define SYS_OK                 0  /* No errors. */
#define SYS_ACCESS_DENIED      1  /* Access denied. */
#define SYS_FILE_NOT_FOUND     2  /* File doesn't exist. */
#define SYS_FILE_EXISTS        3  /* File exists. */
#define SYS_IO                 4  /* I/O error. */
#define SYS_LOCKED             5  /* File is locked. */
#define SYS_ROFS               6  /* Read-only file system. */
#define SYS_UNKNOWN            7  /* Misc. error. */
#define SYS_NOT_ENOUGH_MEMORY  8  /* Not enough memory. */
#define SYS_INVALID_PARAMETER  9  /* Invalid parameter. */


/* Flags for sysOpenFile() (equal to the DosOpen() flags). */
#define SOF_RWMASK             0x000f
#define SOF_READONLY           0x0000
#define SOF_WRITEONLY          0x0001
#define SOF_READWRITE          0x0002

#define SOF_SHMASK             0x00f0
#define SOF_DENYALL            0x0010
#define SOF_DENYWRITE          0x0020
#define SOF_DENYNONE           0x0000

#define SOF_LCMASK             0x0f00 
#define SOF_NO_LOCALITY        0x0000
#define SOF_SEQUENTIAL         0x0100
#define SOF_RANDOM             0x0200
#define SOF_RANDOMSEQUENTIAL   0x0300

#define SOF_NO_CACHE           0x1000
#define SOF_WRITE_THROUGH      0x4000

#define SOF_TRUNC_IF_EXISTS    0x10000
#define SOF_CREATE_IF_NEW      0x20000


SysResult sysOpenFile(char * pszName, int flFlags, Cred cred, 
    File * * ppFile);
SysResult sysCreateFile(char * pszName, int flFlags, 
    FilePos cbInitialSize, Cred cred, File * * ppFile);
SysResult sysCloseFile(File * pFile);
SysResult sysSetFilePos(File * pFile, FilePos ibNewPos);
SysResult sysReadFromFile(File * pFile, FilePos cbLength,
   octet * pabBuffer, FilePos * pcbRead);
SysResult sysWriteToFile(File * pFile, FilePos cbLength,
   octet * pabBuffer, FilePos * pcbWritten);
SysResult sysSetFileSize(File * pFile, FilePos cbSize);
SysResult sysQueryFileSize(File * pFile, FilePos * pcbSize);
SysResult sysDeleteFile(char * pszName, bool fFastDelete, Cred cred);
SysResult sysFileExists(char * pszName, bool * pfExists);

void * sysAllocSecureMem(int cbSize);
void sysFreeSecureMem(void * pMem);
void sysLockMem(); /* disable swapping for future allocations */

void sysInitPRNG();
void sysGetRandomBits(int bits, octet * dst);


#if HAVE_STRICMP
#elif HAVE_STRCASECMP
#define stricmp strcasecmp
#define strnicmp strncasecmp
#else
#error Missing stricmp or strcasecmp!
#endif

#ifndef HAVE_SNPRINTF
int snprintf(char * str, int size, const char * format, ...);
#endif

#endif /* !_SYSDEP_H */
