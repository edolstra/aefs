/* aefsparm.c -- Change settings of the AEFS daemon.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: aefsparm.c,v 1.2 2001/09/23 13:30:16 eelco Exp $

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

#include <stdio.h>
#include <string.h>
#include <os2.h>

#include "aefsdint.h"


int main(int argc, char * * argv)
{
   APIRET rc;
   AEFS_SETPARAMS params;
   ULONG cbParams = sizeof(params);
   char * p = params.szParams;
   int c, i;

   for (c = i = 1; i < argc; i++) {
      c += 1 + strlen(argv[i]);
      if (c > sizeof(params.szParams)) {
         fprintf(stderr, "%s: parameter list too long\n", argv[0]);
         return 1;
      }
      strcpy(p, argv[i]);
      p = strchr(p, 0) + 1;
   }
   *p = 0;

   rc = DosFSCtl(
      NULL, 0, NULL,
      &params, sizeof(params), &cbParams,
      FSCTL_AEFS_SETPARAMS,
      (PSZ) AEFS_IFS_NAME,
      (HFILE) -1,
      FSCTL_FSDNAME);
   if (rc) {
      fprintf(stderr, "%s: error settings parameters, rc = %ld\n",
         argv[0], rc);
      return 1;
   }

   return 0;
}
