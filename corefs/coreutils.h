/* coreutils.h -- Header file to system-independent FS helper code.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: coreutils.h,v 1.4 2001/09/23 13:30:11 eelco Exp $

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

#ifndef _COREUTILS_H
#define _COREUTILS_H

#include "corefs.h"


CoreResult coreQueryIDFromPath(CryptedVolume * pVolume,
   CryptedFileID idStartDir, char * pszPath, CryptedFileID * pid,
   CryptedDirEntry * * ppEntry);

CoreResult coreDeleteFile(CryptedVolume * pVolume, CryptedFileID id);

CoreResult coreAddEntryToDir(CryptedVolume * pVolume, CryptedFileID id,
   char * pszName, CryptedFileID idFile, unsigned int flFlags);

CoreResult coreMoveDirEntry(
   CryptedVolume * pVolume,
   char * pszSrcName,
   CryptedFileID idSrcDir,
   char * pszDstName,
   CryptedFileID idDstDir);


#endif /* !_COREUTILS_H */
