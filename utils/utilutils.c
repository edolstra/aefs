/* utilutils.c -- Helper routines for the utility programs.
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>

#include "utilutils.h"


int readKey(char * pszPrompt, int cbBuffer, char * pszBuffer)
{
   struct termios termios, oldtermios;
   int rc;
   char * p, * envstr;
   int fEchoOff = 0;
   
   fprintf(stderr, pszPrompt);
   fflush(stderr);

   if (isatty(STDIN_FILENO)) {
      envstr = getenv("AEFS_ECHO");
      if (!envstr || !(strcmp(envstr, "1") == 0)) {
         if (tcgetattr(STDIN_FILENO, &termios)) return 1;
         oldtermios = termios;
         termios.c_lflag &= !ECHO;
         if (tcsetattr(STDIN_FILENO, TCSANOW, &termios)) return 1;
         fEchoOff = 1;
      }
   }

   if (!fgets(pszBuffer, cbBuffer, stdin)) 
      rc = 1;
   else {
      rc = 0;
      for (p = pszBuffer; *p && *p != '\n'; p++) ;
      *p = 0;
   }
   
   fprintf(stderr, "\n");

   if (fEchoOff) {
      if (tcsetattr(STDIN_FILENO, TCSANOW, &oldtermios)) return 1;
   }
   
   return 0;
}


Cipher * findCipher(Cipher * * papCipher,
   char * pszCipher, int * pcbBlock, int * pcbKey)
{
   char * pszPos;
   int cchName;

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
