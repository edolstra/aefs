/* types.h -- Declares data types.
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

#ifndef _TYPES_H
#define _TYPES_H

#include "sysspec.h"


typedef int Bool;

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif


/* Interpret the four bytes pointed to by p as a 32-bit unsigned
   integer encoded in little endian format. */
static __inline__ uint32 bytesToInt32(octet * p)
{
   unsigned int i;
   i = *p++;
   i |= *p++ << 8;
   i |= *p++ << 16;
   i |= *p << 24;
   return i;
}


/* Encode the 32-bit unsigned integer i in little endian format. */
static __inline__ void int32ToBytes(uint32 i,
   octet * p)
{
   *p++ = i & 0xff; i >>= 8;
   *p++ = i & 0xff; i >>= 8;
   *p++ = i & 0xff; i >>= 8;
   *p++ = i;
}

     
#endif /* !_TYPES_H */
