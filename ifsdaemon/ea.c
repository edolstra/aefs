/* ea.c -- CryptedEA list <-> FEALIST conversion.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: ea.c,v 1.3 2001/09/23 13:30:13 eelco Exp $

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

#include "aefsdmn.h"


int compareEANames(char * pszName1, char * pszName2) 
{
   return stricmp(pszName1, pszName2);
}


static APIRET mergeEAs(PFEALIST pfeas, CryptedEA * * ppEAs)
{
   CoreResult cr;
   ULONG cbLeft = pfeas->cbList - sizeof(ULONG);
   PFEA pfea = pfeas->list;
   int cbSize;
   char * pszEAName;
   CryptedEA * pNewEA, * pCurEA, * pNextEA, * * ppCurEA;

   while (cbLeft) {
      /* Check the EA. */
      if (cbLeft < sizeof(FEA)) return ERROR_EA_LIST_INCONSISTENT;
      cbSize = sizeof(FEA) + pfea->cbName + 1 + pfea->cbValue;
      if (cbLeft < cbSize)
         return ERROR_EA_LIST_INCONSISTENT;
      pszEAName = sizeof(FEA) + (char *) pfea;

      /* Delete EAs with the same name as the current one. */
      ppCurEA = ppEAs;
      pCurEA = *ppEAs;
      while (pCurEA) {
         pNextEA = pCurEA->pNext;
         if (compareEANames(pCurEA->pszName, pszEAName) == 0) {
            *ppCurEA = pNextEA;
            pCurEA->pNext = 0;
            coreFreeEAs(pCurEA);
         } else
            ppCurEA = &pCurEA->pNext;
         pCurEA = pNextEA;
      }
      
      /* If cbValue is 0, the EA will not be added (i.e. it is
         deleted).  Otherwise, add the EA. */
      if (pfea->cbValue) {
         cr = coreAllocEA(pszEAName, pfea->cbValue,
            (pfea->fEA & FEA_NEEDEA) ? CEF_CRITICAL : 0, &pNewEA);
         if (cr) return coreResultToOS2(cr);
         strupr(pNewEA->pszName);
         memcpy(pNewEA->pabValue, pfea->cbName + 1 + sizeof(FEA) +
            (char *) pfea, pfea->cbValue);
         pNewEA->pNext = *ppEAs;
         *ppEAs = pNewEA;
      }

      /* Go to the next EA. */
      cbLeft -= cbSize;
      pfea = (PFEA) (cbSize + (char *) pfea);
   }

   return NO_ERROR;
}


/* Adds the specified EAs to the file's EA list.  Note that unless all
   EAs are correct, no modification of the file's EA list occurs. */
APIRET addEAs(CryptedVolume * pVolume, CryptedFileID idFile,
   PFEALIST pfeas)
{
   CoreResult cr;
   APIRET rc;
   CryptedEA * pEAs;

   if (pfeas->cbList == sizeof(ULONG)) return NO_ERROR;

   /* Get the current EA set. */
   cr = coreQueryEAs(pVolume, idFile, &pEAs);
   if (cr) return coreResultToOS2(cr);

   /* Apply the given EA list. */
   rc = mergeEAs(pfeas, &pEAs);
   if (rc) {
      coreFreeEAs(pEAs);
      return rc;
   }

   /* Set the new EA set. */
   cr = coreSetEAs(pVolume, idFile, pEAs);
   coreFreeEAs(pEAs);
   if (cr) return coreResultToOS2(cr);

   return NO_ERROR;
}


static APIRET storeEA(char * pszName, int cbValue, octet * pabValue,
   ULONG * pcbData, PFEA * ppfea)
{
   int cbName, cbSize;
   PFEA pfea = *ppfea;
   
   cbName = strlen(pszName);
   cbSize = sizeof(FEA) + cbName + 1 + cbValue;

   /* Enough space? */
   if (*pcbData < cbSize) return ERROR_BUFFER_OVERFLOW;
   
   /* Copy the EA to the FEA. */
   pfea->fEA = 0;
   pfea->cbName = cbName;
   pfea->cbValue = cbValue;
   memcpy(sizeof(FEA) + (char *) pfea, pszName, cbName + 1);
   if (cbValue)
      memcpy(sizeof(FEA) + cbName + 1 + (char *) pfea,
         pabValue, cbValue);
   
   *ppfea = (PFEA) (cbSize + (char *) pfea);
   *pcbData -= cbSize;

   return NO_ERROR;
}


static APIRET storeMatchingEAs(CryptedEA * pEAs,
   char * pszName, ULONG * pcbData, PFEA * ppfea)
{
   APIRET rc;
   CryptedEA * pCur;
   ULONG cbData = *pcbData;
   PFEA pfea = *ppfea;
   bool fMatch = 0;
   
   /* Store each matching EA. */
   for (pCur = pEAs; pCur; pCur = pCur->pNext)
      if (!pszName || (compareEANames(pszName, pCur->pszName) == 0)) {
         rc = storeEA(pCur->pszName, pCur->cbValue, pCur->pabValue,
            &cbData, &pfea);
         if (rc) return rc;
         fMatch = 1;
      }

   /* If the specified EA was not found, we store a FEA with an empty
      value (i.e. cbValue = 0). */
   if (pszName && !fMatch) {
      rc = storeEA(pszName, 0, 0, &cbData, &pfea);
      if (rc) return rc;
   }

   *pcbData = cbData;
   *ppfea = pfea;

   return NO_ERROR;
}


static APIRET storeEAsInFEAList2(CryptedEA * pEAs,
   CryptedFileInfo * pinfo,
   PGEALIST pgeas, ULONG cbData, char * pData)
{
   APIRET rc;
   PFEALIST pfeas = (PFEALIST) pData;
   PFEA pfea = pfeas->list;
   PGEA pgea;
   int cbLeft;

   if (cbData < 4) return ERROR_BUFFER_OVERFLOW;

   /* In case of a buffer overflow, cbList is expected to be the size
      of the EAs on disk. */ 
   pfeas->cbList = pinfo->cbEAs;
   cbData -= 4;

   if (pgeas) {
      
      /* Store EAs matching the GEA list. */
      pgea = pgeas->list;
      cbLeft = pgeas->cbList;
      if (cbLeft < 4) return ERROR_EA_LIST_INCONSISTENT;
      cbLeft -= 4;
      while (cbLeft) {
         if ((cbLeft < pgea->cbName + 2) ||
             (pgea->szName[pgea->cbName]))
            return ERROR_EA_LIST_INCONSISTENT;
         rc = storeMatchingEAs(pEAs, pgea->szName, &cbData, &pfea);
         if (rc) return rc;
         cbLeft -= pgea->cbName + 2;
         pgea = (PGEA) (pgea->cbName + 2 + (char *) pgea);
      }
      
   } else {

      /* Store all EAs. */
      rc = storeMatchingEAs(pEAs, 0, &cbData, &pfea);
      if (rc) return rc;
      
   }

   pfeas->cbList = (char *) pfea - (char *) pData;

   return NO_ERROR;
}

     
/* Stores the EAs specified by pgeas in the buffer.  If pgeas = 0 all
   EAs are to be stored. */
APIRET storeEAsInFEAList(CryptedVolume * pVolume,
   CryptedFileID idFile, CryptedFileInfo * pinfo,
   PGEALIST pgeas, ULONG cbData, char * pData)
{
   CoreResult cr;
   APIRET rc;
   CryptedEA * pEAs;

   /* Get the current EA set. */
   cr = coreQueryEAs(pVolume, idFile, &pEAs);
   if (cr) return coreResultToOS2(cr);

   rc = storeEAsInFEAList2(pEAs, pinfo, pgeas, cbData, pData);
   coreFreeEAs(pEAs);
   if (rc) return rc;

   return NO_ERROR;
}
