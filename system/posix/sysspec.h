/* sysspec.h -- Posix-specific definitions.
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

#ifndef _SYSSPEC_H
#define _SYSSPEC_H

#include <sys/types.h>


/* Override these to match your system. */


/* uint8 should be an unsigned integer *at least* 8 bits wide. */
typedef unsigned char uint8;

/* uint16 should be an unsigned integer *at least* 16 bits wide. */
typedef unsigned short uint16;

/* uint32 should be an unsigned integer *at least* 32 bits wide. */
typedef unsigned int uint32;

/* octet should be an unsigned integer precisely 8 bits wide. */
typedef unsigned char octet;


#define IS_PATH_SEPARATOR(c) ((c) == '/')


typedef struct {
      int fEnforce;
      uid_t uid;
      gid_t gid;
      mode_t mode;
} Cred;


#endif
