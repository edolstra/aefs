/* comparators.h -- Filename comparators.
   Copyright (C) 2002 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: comparators.h,v 1.2 2002/01/14 21:36:42 eelco Exp $

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

#ifndef _COMPARATORS_H
#define _COMPARATORS_H

#include "types.h"

typedef int (* CoreNameComp)(octet *, octet *);

int coreNameCompSens(octet *, octet *);
int coreNameCompInsens(octet *, octet *);

#endif /* !_COMPARATORS_H */