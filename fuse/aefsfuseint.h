/* aefsfuseint.c -- Interface between aefsfuse and mntaefsfuse.
   Copyright (C) 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: aefsfuseint.h,v 1.1 2001/12/26 21:49:58 eelco Exp $

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

#ifndef _AEFSFUSEINT_H
#define _AEFSFUSEINT_H

#include <limits.h>

#include "superblock.h"

typedef struct {
    bool fDebug;
    bool fReadOnly;
    bool fMountDirty;
    char szBasePath[PATH_MAX + 16];
    char szMountPoint[PATH_MAX];
    char szPassPhrase[MAX_PASSPHRASE_SIZE];
} FuseMountParams;

#endif /* !_AEFSFUSEINT_H */
