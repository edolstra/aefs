/* utilutils.c -- Helper routines for the utility programs.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: utilutils.c,v 1.8 2001/09/23 13:30:25 eelco Exp $

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>

#include "utilutils.h"


int readKey(char * pszPrompt, unsigned int cbBuffer, char * pszBuffer)
{
   char * p, * envstr;
   
   envstr = getenv("AEFS_ECHO");
   if (envstr && (strcmp(envstr, "1") == 0)) {
      fprintf(stderr, "%s", pszPrompt);
      if (!fgets(pszBuffer, cbBuffer, stdin)) return 1;
      for (p = pszBuffer; *p && *p != '\n'; p++) ;
      *p = 0;
   } else {
      /* !!! On some systems (e.g. Irix 5.3), getpass() is restricted
         to 8 characters. */
      p = getpass(pszPrompt);
      if (!p) return 1;
      strcpy(pszBuffer, p);
      memset(p, 0, strlen(p));
   }
   return 0;
}


Cipher * findCipher(Cipher * * papCipher,
   char * pszCipher, unsigned int * pcbBlock, unsigned int * pcbKey)
{
   char * pszPos;
   unsigned int cchName;

   *pcbBlock = 0;
   *pcbKey = 0;

   /* Parse pszCipher. */
   pszPos = strchr(pszCipher, '-');
   if (pszPos) {
      cchName = pszPos - pszCipher;
      if (strchr(pszPos + 1, '-')) {
         if (sscanf(pszPos + 1, "%d-%d",
            pcbKey, pcbBlock) != 2)
            return 0;
      }
      else
         if (sscanf(pszPos + 1, "%d", pcbKey) == EOF)
            return 0;
   }
   else
      cchName = strlen(pszCipher);

   *pcbBlock /= 8;
   *pcbKey /= 8;

   for ( ; *papCipher; papCipher++)
      if ((strlen((*papCipher)->pszID) == cchName) &&
          (strncmp((*papCipher)->pszID, pszCipher, cchName) == 0))
      {
         if (*pcbBlock == 0)
            *pcbBlock = (*papCipher)->paSizes->cbBlock;
         if (*pcbKey == 0)
            *pcbKey = (*papCipher)->paSizes->cbKey;
         return *papCipher;
      }

   return 0;
}


char * core2str(CoreResult cr)
{
    switch (cr) {
        case CORERC_OK: return "no error";
        case CORERC_FILE_NOT_FOUND: return "file not found";
        case CORERC_NOT_ENOUGH_MEMORY: return "out of memory";
        case CORERC_FILE_EXISTS: return "file exists";
        case CORERC_INVALID_PARAMETER: return "invalid parameter";
        case CORERC_INVALID_NAME: return "invalid file name";
        case CORERC_BAD_CHECKSUM: return "bad checksum (wrong key?)";
        case CORERC_BAD_INFOSECTOR: return "bad infosector";
        case CORERC_NOT_DIRECTORY: return "not a directory";
        case CORERC_BAD_DIRECTORY: return "corrupt directory";
        case CORERC_BAD_TYPE: return "bad file type";
        case CORERC_BAD_EAS: return "corrupt extended attributes";
        case CORERC_CACHE_OVERFLOW: return "cache overflow";
        case CORERC_READ_ONLY: return "file system is read-only";
        case CORERC_ISF_CORRUPT: return "corrupt infosector file";
        case CORERC_ID_EXISTS: return "file ID exists";
        case CORERC_SYS + SYS_ACCESS_DENIED:
            return "access denied to storage file";
        case CORERC_SYS + SYS_FILE_NOT_FOUND:
            return "storage file not found";
        case CORERC_SYS + SYS_FILE_EXISTS:
            return "storage file exists";
        case CORERC_SYS + SYS_IO:
            return "I/O error accessing storage file";
        case CORERC_SYS + SYS_LOCKED:
            return "storage file is locked";
        case CORERC_SYS + SYS_ROFS:
            return "storage file is on a read-only file system";
        case CORERC_SYS + SYS_UNKNOWN:
            return "unknown error accessing storage file";
        default: return "unknown error";
    }
}
