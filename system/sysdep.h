/* sysdep.h -- Interface to system-dependent stuff needed by the
   system-independent FS code.
   Copyright (C) 1999 Eelco Dolstra (edolstra@students.cs.uu.nl).

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


typedef struct _File File;
typedef long FilePos;


/* Flags for sysOpenFile() (equal to the DosOpen() flags). */
#define SOF_RWMASK             0x000f
#define SOF_READONLY           0x0000
#define SOF_WRITEONLY          0x0001
#define SOF_READWRITE          0x0002

#define SOF_SHMASK             0x00f0
#define SOF_DENYREADWRITE      0x0010
#define SOF_DENYWRITE          0x0020
#define SOF_DENYREAD           0x0030
#define SOF_DENYNONE           0x0040

#define SOF_LCMASK             0x0f00 
#define SOF_NO_LOCALITY        0x0000
#define SOF_SEQUENTIAL         0x0100
#define SOF_RANDOM             0x0200
#define SOF_RANDOMSEQUENTIAL   0x0300

#define SOF_NO_CACHE           0x1000
#define SOF_WRITE_THROUGH      0x4000

#define SOF_EXMASK             0x000f0000 
#define SOF_FAIL_IF_EXISTS     0x00000000
#define SOF_OPEN_IF_EXISTS     0x00010000
#define SOF_REPLACE_IF_EXISTS  0x00020000
#define SOF_NXMASK             0x00f00000 
#define SOF_FAIL_IF_NEW        0x00000000
#define SOF_CREATE_IF_NEW      0x00100000  


File * sysOpenFile(char * pszName, int flFlags,
   FilePos cbInitialSize);
Bool sysCloseFile(File * pFile);
Bool sysSetFilePos(File * pFile, FilePos ibNewPos);
Bool sysReadFromFile(File * pFile, FilePos cbLength,
   octet * pabBuffer, FilePos * pcbRead);
Bool sysWriteToFile(File * pFile, FilePos cbLength,
   octet * pabBuffer, FilePos * pcbWritten);
Bool sysSetFileSize(File * pFile, FilePos cbSize);
Bool sysQueryFileSize(File * pFile, FilePos * pcbSize);
Bool sysDeleteFile(char * pszName, Bool fFastDelete);
Bool sysFileExists(char * pszName);

void * sysAllocSecureMem(int cbSize);
void sysFreeSecureMem(void * pMem);

void sysInitPRNG();
void sysGetRandomBits(int bits, octet * dst);


#if HAVE_STRICMP
#elif HAVE_STRCASECMP
#define stricmp strcasecmp
#define strnicmp strncasecmp
#else
#error Missing stricmp or strcasecmp!
#endif

#endif /* !_SYSDEP_H */
