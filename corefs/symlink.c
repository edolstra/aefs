/* symlink.c -- Symlink support.
   Copyright (C) 2005 Eelco Dolstra (eelco@cs.uu.nl).

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

#include <string.h>

#include "corefs.h"
#include "sysdep.h"


CoreResult coreWriteSymlink(CryptedVolume * pVolume,
   CryptedFileID id, const char * pszTarget)
{
   CoreResult cr;
   CryptedFileInfo info;
    
   cr = coreQueryFileInfo(pVolume, id, &info);
   if (cr) return cr;

   if (!CFF_ISLNK(info.flFlags)) return CORERC_NOT_SYMLINK;

   CryptedEA * pEAs, * pCurEA, * * ppPrevEA;
   cr = coreQueryEAs(pVolume, id, &pEAs);
   if (cr) return cr;

   /* Remove the current CEA_SYMLINK attribute. */
   for (pCurEA = pEAs, ppPrevEA = &pEAs; pCurEA; )
   {
      if (strcmp(pCurEA->pszName, CEANAME_SYMLINK) == 0) {
         *ppPrevEA = pCurEA->pNext;
         pCurEA->pNext = 0;
         coreFreeEAs(pCurEA);
         pCurEA = *ppPrevEA;
      } else {
         ppPrevEA = &pCurEA->pNext;
         pCurEA = pCurEA->pNext;
      }
   }

   CryptedEA * pNewEA;
   cr = coreAllocEA(CEANAME_SYMLINK, strlen(pszTarget), CEF_CRITICAL, &pNewEA);
   if (cr) {
      coreFreeEAs(pEAs);
      return cr;
   }

   strncpy((char *) pNewEA->pabValue, pszTarget, strlen(pszTarget));
   pNewEA->pNext = pEAs;
   
   cr = coreSetEAs(pVolume, id, pNewEA);
      
   coreFreeEAs(pNewEA);

   return cr;
}


CoreResult coreReadSymlink(CryptedVolume * pVolume,
   CryptedFileID id, unsigned int cbMaxTarget, char * pszTarget)
{
   CoreResult cr;
   CryptedFilePos cbRead;
   CryptedFileInfo info;
    
   cr = coreQueryFileInfo(pVolume, id, &info);
   if (cr) return cr;

   if (!CFF_ISLNK(info.flFlags)) return CORERC_NOT_SYMLINK;

   CryptedEA * pEAs, * pCurEA;
   cr = coreQueryEAs(pVolume, id, &pEAs);
   if (cr) return cr;

   for (pCurEA = pEAs; pCurEA; pCurEA = pCurEA->pNext) {
      if (strcmp(pCurEA->pszName, CEANAME_SYMLINK) == 0) {
         if (pCurEA->cbValue >= cbMaxTarget) {
            coreFreeEAs(pEAs);
            return CORERC_NAME_TOO_LONG;
         }
         strncpy(pszTarget, (char *) pCurEA->pabValue, pCurEA->cbValue);
         pszTarget[pCurEA->cbValue] = 0;
         coreFreeEAs(pEAs);
         return 0;
      }
   }
   
   coreFreeEAs(pEAs);
    
   /* Use old-style symlinks, which store the target in the file
      contents. */
   if (info.cbFileSize == 0) return CORERC_BAD_SYMLINK;
   if (info.cbFileSize >= cbMaxTarget) return CORERC_NAME_TOO_LONG;
                                            
   cr = coreReadFromFile(pVolume, id, 0,
      info.cbFileSize, (octet *) pszTarget, &cbRead);
   if (cr) return cr;
   pszTarget[info.cbFileSize] = 0;

   return CORERC_OK;
}

