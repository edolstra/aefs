/* sysspec.h -- OS/2 (EMX)-specific definitions. 
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: sysspec.h,v 1.5 2001/09/23 13:30:21 eelco Exp $

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


#define IS_PATH_SEPARATOR(c) (((c) == '/') || ((c) == '\\'))

/* # of bytes allocated using sysAllocSecureMem. */
extern int cbSecureAlloced; 
/* # of bytes freed using sysFreeSecureMem. */
extern int cbSecureFreed;
/* # of calls to sysAllocSecureMem. */
extern int cSecureAlloced;
/* # of calls to sysFreeSecureMem. */
extern int cSecureFreed;


/* OS/2 is not multi-user. */
typedef struct {
      int _dummy_; /* to silence warnings */
} Cred;


#endif
