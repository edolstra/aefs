/* logging.h -- Header file to the logging support code.
   Copyright (C) 2001 Eelco Dolstra (eelco@cs.uu.nl).

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

#ifndef _LOGGING_H
#define _LOGGING_H

#include <syslog.h>

#include "types.h"

extern bool fDebug;

void logMsg(int level, char * pszMsg, ...);

#endif /* !_LOGGING_H */
