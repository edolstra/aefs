/* aefsck.h -- Return codes of aefsck.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: aefsck.h,v 1.2 2001/09/23 13:30:24 eelco Exp $

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

#ifndef _AEFSCK_H
#define _AEFSCK_H


/* The return code of aefsck is the bitwise OR of the following: */
  
#define AEFSCK_ERRORFOUND  1 /* errors were found */
#define AEFSCK_NOTFIXED    2 /* some errors were not fixed */
#define AEFSCK_ABORT       8 /* aefsck could not continue */
#define AEFSCK_FAIL       16 /* aefsck itself failed (bug, out of
                                memory, etc.) */
#define AEFSCK_INTERRUPT  32 /* aefsck was interrupted by the user */


#endif /* !_AEFSCK_H */
