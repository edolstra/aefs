/* aefsdint.h -- External interface to the AEFS FSD.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: aefsdint.h,v 1.3 2001/09/23 13:30:12 eelco Exp $

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

#ifndef _AEFSDINT_H
#define _AEFSDINT_H


#include "stubfsd.h"


#define AEFS_IFS_NAME "AEFS"


#define ERROR_AEFS_BASE          (ERROR_STUBFSD_BASE + 100)
#define ERROR_AEFS_DIRTY         (ERROR_AEFS_BASE + 0) /* volume is dirty */
#define ERROR_AEFS_SETAEFSPARAMS (ERROR_AEFS_BASE + 1) /* error settings params */


/* FSCTL_AEFS_SETPARAMS sets daemon parameters. */
#define FSCTL_AEFS_SETPARAMS      0x8020


/* Flags for ATTACHPARMS.flFlags. */
#define AP_READONLY            1  /* do not modify the volume in any way */
#define AP_MOUNTDIRTY          2  /* mount even if dirty */


/* Flags for DETACHPARMS.flFlags. */
#define DP_FORCE               1  /* unmount even if unable to flush */


/* Structure for DosFSAttach, subcode FS_ATTACH. */
typedef struct {
      ULONG flFlags;
      CHAR szBasePath[CCHMAXPATH];
      CHAR szKey[256];
} AEFS_ATTACH;


/* Structure for DosFSAttach, subcode FS_DETACH. */
typedef struct {
      ULONG flFlags;
} AEFS_DETACH;


/* Structure for FSCTL_AEFS_SETPARAMS. */
typedef struct {
      /* Array of zero-terminated strings, zero-terminated.  For
         example, "Foo" \000 "Bar" \000 \000. */
      CHAR szParams[1024];
} AEFS_SETPARAMS;


#endif /* !_AEFSDINT_H */
