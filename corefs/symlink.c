/* symlink.c -- Symlink support.
   Copyright (C) 2005 Eelco Dolstra (eelco@cs.uu.nl).

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

#include <string.h>

#include "corefs.h"
#include "sysdep.h"


CoreResult coreWriteSymlink(CryptedVolume * pVolume,
   CryptedFileID id, char * pszTarget)
{
   CryptedFilePos cbWritten;
   return coreWriteToFile(pVolume, id, 0,
      strlen(pszTarget), (octet *) pszTarget, &cbWritten);
}


CoreResult coreReadSymlink(CryptedVolume * pVolume,
   CryptedFileID id, unsigned int cbMaxTarget, char * * pszTarget)
{
    CoreResult cr;
    CryptedFilePos cbRead;
    CryptedFileInfo info;
    
    cr = coreQueryFileInfo(pVolume, id, &info);
    if (cr) return cr;

    if (!CFF_ISLNK(info.flFlags)) return CORERC_NOT_SYMLINK;
    if (info.cbFileSize >= cbMaxTarget) return CORERC_NAME_TOO_LONG;

    cr = coreReadFromFile(pVolume, id, 0,
        info.cbFileSize, (octet *) *pszTarget, &cbRead);
    if (cr) return cr;
    (*pszTarget)[info.cbFileSize] = 0;

    return CORERC_OK;
}

