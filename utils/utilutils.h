/* utilutils.h -- Helper routines for the utility programs.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

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

#ifndef _UTILUTILS_H
#define _UTILUTILS_H

#include "cipher.h"
#include "corefs.h"

int readPhrase(char * pszPrompt, 
    unsigned int cbBuffer, char * pszBuffer);

Cipher * findCipher(Cipher * * papCipher,
   char * pszCipher, unsigned int * pcbBlock, unsigned int * pcbKey);

char * core2str(CoreResult cr);


#define STANDARD_KEY_HELP "\
If the passphrase is not specified on the command-line, the user is\n\
asked to enter it interactively (with echo if the environment variable\n\
AEFS_ECHO is set to `1').\n\
"

#endif /* !_UTITUTILS_H */
