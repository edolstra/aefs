/* infosector.c -- Maintains the info sector file (ISF).
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: infosector.c,v 1.3 2001/09/23 13:30:11 eelco Exp $

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

#include <assert.h>

#include "corefs.h"


CoreResult coreInitISF(CryptedVolume * pVolume)
{
   CoreResult cr;
   CryptedFileInfoFreeLink link;

   int32ToBytes(INFOSECTOR_MAGIC_FREE, link.magic);
   int32ToBytes(0, link.idNextFree);
   int32ToBytes(1, link.csSize);

   cr = coreSetSectorData(pVolume, INFOSECTORFILE_ID, 0,
      0, sizeof(CryptedFileInfoFreeLink), CFETCH_NO_READ, &link);
   if (cr) return cr;
   
   return CORERC_OK;
}


CoreResult coreAllocID(CryptedVolume * pVolume, CryptedFileID * pid)
{
   CoreResult cr;
   CryptedFileInfoFreeLink sentinel, link;
   CryptedFileID idFree;
   SectorNumber csSize;
   CryptedFileID idNewHead;
   SectorNumber csGrow;
   CryptedFileID idClear;

   *pid = 0;

   /* Get the sentinel, which contains the head of the linked list of
      free info sectors. */
   cr = coreQuerySectorData(pVolume, INFOSECTORFILE_ID, 0,
      0, sizeof(CryptedFileInfoFreeLink), 0, &sentinel);
   if (cr) return cr;
   
   if (bytesToInt32(sentinel.magic) != INFOSECTOR_MAGIC_FREE)
      return CORERC_ISF_CORRUPT;
   idFree = bytesToInt32(sentinel.idNextFree);
   csSize = bytesToInt32(sentinel.csSize);
   if (idFree >= csSize) return CORERC_ISF_CORRUPT;
   
   if (idFree) { /* non-empty linked list */

      /* Now we have to find the new head of the linked list, which is
         the successor of the current head. */
      cr = coreQuerySectorData(pVolume, INFOSECTORFILE_ID, idFree,
         0, sizeof(CryptedFileInfoFreeLink), 0, &link);
      if (cr) return cr;
      
      if (bytesToInt32(link.magic) != INFOSECTOR_MAGIC_FREE)
         return CORERC_ISF_CORRUPT;
      idNewHead = bytesToInt32(link.idNextFree);
      if (idNewHead >= csSize) return CORERC_ISF_CORRUPT;

   } else { /* empty linked list */

      /* Grow the ISF by csISFGrow sectors. */
      csGrow = coreQueryVolumeParms(pVolume)->csISFGrow;
      assert(csGrow >= 1);
      cr = coreSuggestFileAllocation(pVolume, INFOSECTORFILE_ID, csSize + csGrow);
      if (cr) return cr;

      /* Add the {2..csISFGrow}th new sectors to the free list. */
      for (idClear = csSize + 1; idClear < csSize + csGrow; idClear++)
      {
         int32ToBytes(INFOSECTOR_MAGIC_FREE, link.magic);
         int32ToBytes(idClear == csSize + csGrow - 1 ?
            0 : idClear + 1, link.idNextFree);
         int32ToBytes(0, link.csSize);

         cr = coreSetSectorData(pVolume, INFOSECTORFILE_ID, idClear,
            0, sizeof(CryptedFileInfoFreeLink), CFETCH_NO_READ, &link);
         if (cr) return cr;
      }
      
      idNewHead = csGrow > 1 ? csSize + 1 : 0;

      /* The 1st new sector is the newly allocated info sector.  Force
         it into the cache. */
      idFree = csSize;
      cr = coreFetchSectors(pVolume, INFOSECTORFILE_ID, idFree, 1,
         CFETCH_NO_READ);

      csSize += csGrow;
   }

   /* Note that it's the caller's responsibility to do something with
      sector idFree.  We're not even going to clear the magic
      value. */

   /* Update the sentinel. */
   int32ToBytes(idNewHead, sentinel.idNextFree);
   int32ToBytes(csSize, sentinel.csSize);
   
   cr = coreSetSectorData(pVolume, INFOSECTORFILE_ID, 0,
      0, sizeof(CryptedFileInfoFreeLink), 0, &sentinel);
   if (cr) return cr;
   
   *pid = idFree;
   
   return CORERC_OK;
}


CoreResult coreFreeID(CryptedVolume * pVolume, CryptedFileID id)
{
   CoreResult cr;
   CryptedFileInfoFreeLink sentinel, link;
   CryptedFileID idFree;
   SectorNumber csSize;

   /* Get the sentinel, which contains the head of the linked list of
      free info sectors. */
   cr = coreQuerySectorData(pVolume, INFOSECTORFILE_ID, 0,
      0, sizeof(CryptedFileInfoFreeLink), 0, &sentinel);
   if (cr) return cr;

   if (bytesToInt32(sentinel.magic) != INFOSECTOR_MAGIC_FREE)
      return CORERC_ISF_CORRUPT;
   idFree = bytesToInt32(sentinel.idNextFree);
   csSize = bytesToInt32(sentinel.csSize);
   if ((idFree >= csSize) || (id >= csSize)) return CORERC_ISF_CORRUPT;

   /* Make info sector id a free element, and make the current head of
      the list into the successor of id. */
   int32ToBytes(INFOSECTOR_MAGIC_FREE, link.magic);
   int32ToBytes(idFree, link.idNextFree);
   int32ToBytes(0, link.csSize);
   
   cr = coreSetSectorData(pVolume, INFOSECTORFILE_ID, id,
      0, sizeof(CryptedFileInfoFreeLink), 0, &link);
   if (cr) return cr;
   
   /* Make id the new head of the list. */
   int32ToBytes(id, sentinel.idNextFree);

   cr = coreSetSectorData(pVolume, INFOSECTORFILE_ID, 0,
      0, sizeof(CryptedFileInfoFreeLink), 0, &sentinel);
   if (cr) return cr;
   
   return CORERC_OK;
}
