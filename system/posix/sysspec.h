/* sysspec.h -- Posix-specific definitions.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: sysspec.h,v 1.5 2001/09/23 13:30:23 eelco Exp $

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

#ifndef _SYSSPEC_H
#define _SYSSPEC_H

#include <sys/types.h>


#define IS_PATH_SEPARATOR(c) ((c) == '/')


typedef struct {
      int fEnforce;
      uid_t uid;
      gid_t gid;
      mode_t mode;
} Cred;


#endif
