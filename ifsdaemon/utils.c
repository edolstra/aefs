/* utils.c -- Helper routines for the daemon.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: utils.c,v 1.10 2001/09/23 13:56:30 eelco Exp $

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
#include <time.h>
#include <assert.h>

#include "aefsdmn.h"
#include "sysdep.h"


/* Verify that the specified string is no longer than cbMaxLen bytes;
   i.e. the null character should be encountered within cbMaxLen bytes
   from pszStr.  Return 1 iff the string is too long. */
int verifyString(char * pszStr, int cbMaxLen)
{
   while (cbMaxLen--) if (!*pszStr++) return 0;
   logMsg(L_DBG, "string too long");
   return 1;
}


/* Verify that the specified string starts with "x:\" ("x" being a
   random character).  Return 1 iff it isn't so. */
int verifyPathName(char * pszName)
{
   return
      (!*pszName) ||
      (pszName[1] != ':') ||
      ((pszName[2] != '/') && (pszName[2] != '\\'));
}


/* Invalid characters for DOS file names (from CP Guide & Reference,
   "File Names in the FAT File System"). */
#define DOSBADCHARS "<>|+=:;,.\"/\\[]"


/* Return true iff the specified name is not a valid DOS (that is,
   8.3) filename. */
bool hasNon83Name(char * pszName)
{
   char * p;
   int ext = 0, i = 0;
   if ((strcmp(pszName, ".") == 0) ||
       (strcmp(pszName, "..") == 0))
      return false;
   for (p = pszName; *p; p++) {
      i++;
      if (ext) {
         if (*p == '.') return true;
         if (i > 3) return true;
         if (strchr(DOSBADCHARS, *p)) return true;
      } else {
         if (*p == '.') {
            ext = 1;
            i = 0;
         } else {
            if (i > 8) return true;
            if (strchr(DOSBADCHARS, *p)) return true;
         }
      }
   }
   return false;
}


APIRET coreResultToOS2(CoreResult cr)
{
   switch (cr) {
      case CORERC_OK: return NO_ERROR;
      case CORERC_FILE_NOT_FOUND: return ERROR_FILE_NOT_FOUND;
      case CORERC_NOT_ENOUGH_MEMORY: return ERROR_NOT_ENOUGH_MEMORY;
      case CORERC_FILE_EXISTS: return ERROR_FILE_EXISTS;
      case CORERC_INVALID_PARAMETER: return ERROR_INVALID_PARAMETER;
      case CORERC_INVALID_NAME: return ERROR_INVALID_NAME;
      case CORERC_BAD_CHECKSUM: return ERROR_CRC;
      case CORERC_NOT_DIRECTORY: return ERROR_PATH_NOT_FOUND;
      case CORERC_READ_ONLY: return ERROR_WRITE_PROTECT;
      default:
         if (IS_CORERC_SYS(cr))
            return ERROR_SEEK;
         return ERROR_AEFS_BASE + 100 + cr;
   }
}


/* Split a path into its last component and the stuff that precedes
   it (minus the separating (back)slash).
   Examples:
   "/foo/bar" -> ("/foo", "bar")
   "/foo/bar/" -> ("/foo/bar", "")
   "/foo" -> ("", "foo")
   "foo" -> ("", "foo") (special case)
   (All paths must begin with a (back)slash).
   The buffers pointed to by pszPrefix and pszLast must be at least
   CCHMAXPATH bytes large, and pszFull must be no more than CCHMAXPATH
   bytes large. */
void splitPath(char * pszFull, char * pszPrefix, char * pszLast)
{
   char * p, * p2;

   p = pszFull;
   p2 = 0;

   while (*p) {
      if (IS_PATH_SEPARATOR(*p)) p2 = p;
      p++;
   }

   if (!p2) {
      *pszPrefix = 0;
      strcpy(pszLast, pszFull);
      return;
   }

   strcpy(pszLast, p2 + 1);

   while (!IS_PATH_SEPARATOR(*p2))
      if (p2-- == pszFull) {
         *pszPrefix = 0;
         return;
      }

   memcpy(pszPrefix, pszFull, p2 - pszFull + 1);
   pszPrefix[p2 - pszFull + 1] = 0;
}


void logsffsi(struct sffsi * psffsi)
{
   logMsg(L_DBG,
      "sfi_mode=%08lx, sfi_size=%08lx, sfi_position=%08lx, "
      "sfi_PID=%04hx, sfi_PDB=%04hx, sfi_selfsfn=%04hx, "
      "sfi_tstamp=%02x, sfi_type=%04hx, sfi_DOSattr=%04hx",
      psffsi->sfi_mode,
      psffsi->sfi_size,
      psffsi->sfi_position,
      psffsi->sfi_PID,
      psffsi->sfi_PDB,
      psffsi->sfi_selfsfn,
      (int) psffsi->sfi_tstamp,
      psffsi->sfi_type,
      psffsi->sfi_DOSattr);
}


void coreToSffsi(bool fHidden, CryptedFileInfo * pInfo,
   struct sffsi * psffsi)
{
   coreTimeToOS2(pInfo->timeCreation,
      (FDATE *) &psffsi->sfi_cdate, (FTIME *) &psffsi->sfi_ctime);
   coreTimeToOS2(pInfo->timeAccess,
      (FDATE *) &psffsi->sfi_adate, (FTIME *) &psffsi->sfi_atime);
   coreTimeToOS2(pInfo->timeWrite,
      (FDATE *) &psffsi->sfi_mdate, (FTIME *) &psffsi->sfi_mtime);
   psffsi->sfi_size = pInfo->cbFileSize;
   psffsi->sfi_type = (psffsi->sfi_type & STYPE_FCB) | STYPE_FILE;
   psffsi->sfi_DOSattr &= ~FILE_NON83;
   psffsi->sfi_DOSattr |= makeDOSAttr(fHidden, pInfo);
}


USHORT makeDOSAttr(bool fHidden, CryptedFileInfo * pInfo)
{
   return 
      (fHidden ? FILE_HIDDEN : 0) |
      (CFF_ISDIR(pInfo->flFlags) ? FILE_DIRECTORY : 0) |
      ((pInfo->flFlags & CFF_OS2A) ? FILE_ARCHIVED : 0) |
      ((pInfo->flFlags & CFF_OS2S) ? FILE_SYSTEM : 0) |
      ((pInfo->flFlags & CFF_IWUSR) ? 0 : FILE_READONLY);
}


void extractDOSAttr(USHORT fsAttr, CryptedFileInfo * pInfo)
{
   pInfo->flFlags &= ~(CFF_OS2A | CFF_OS2S | CFF_IWUSR);
   pInfo->flFlags |=
      ((fsAttr & FILE_ARCHIVED) ? CFF_OS2A : 0) |
      ((fsAttr & FILE_SYSTEM) ? CFF_OS2S : 0) |
      ((fsAttr & FILE_READONLY) ? 0 : CFF_IWUSR);
}


CoreTime curTime()
{
   return (CoreTime) time(0);
}


int coreTimeToOS2(CoreTime time, FDATE * pfdate, FTIME * pftime)
{
   static FDATE mindate = { 1, 1, 0 /* = 1980 */ };
   static FTIME mintime = { 0, 0, 0 };
   static FDATE maxdate = { 12, 31, 127 /* = 2107 */ };
   static FTIME maxtime = { 29, 59, 23 };
   
   time_t t = (time_t) time;
   struct tm * tm = localtime(&t);

   if (tm->tm_year < 80 /* 1980 */ ) {
      *pfdate = mindate;
      *pftime = mintime;
      return 1;
   } else if (tm->tm_year > 107 /* 2107 */ ) {
      *pfdate = maxdate;
      *pftime = maxtime;
      return 1;
   } else {
      pfdate->year = tm->tm_year - 80;
      pfdate->month = tm->tm_mon + 1;
      pfdate->day = tm->tm_mday;
      pftime->hours = tm->tm_hour;
      pftime->minutes = tm->tm_min;
      pftime->twosecs = tm->tm_sec / 2;
      return 0;
   }
}


int os2TimeToCore(FDATE fdate, FTIME ftime, CoreTime * ptime)
{
   struct tm tm;
   time_t t;

   tm.tm_year = fdate.year + 80;
   tm.tm_mon = fdate.month - 1;
   tm.tm_mday = fdate.day;
   tm.tm_hour = ftime.hours;
   tm.tm_min = ftime.minutes;
   tm.tm_sec = ftime.twosecs * 2;
   tm.tm_isdst = -1;

   t = mktime(&tm);
   if (t == (time_t) -1) return 1;
   *ptime = (CoreTime) t;
   return 0;
}


CoreResult findFromCurDir(VolData * pVolData, char * szPath,
   struct cdfsi * pcdfsi, CDFSD * pcdfsd, USHORT iCurDirEnd,
   CryptedFileID * pidDir, CryptedFileID * pidFile,
   CryptedDirEntry * * ppDirEntry, char * szName)
{
   CoreResult cr;
   CHAR szDir[CCHMAXPATH];
   CryptedFileID idStart;

   logMsg(L_DBG, "looking up: %s, curdir=%s, id=%08x, iCurDirEnd=%hd",
      szPath, pcdfsi->cdi_curdir, (CryptedFileID) pcdfsd->data[0],
      iCurDirEnd);

   *pidDir = 0;
   *pidFile = 0;
   
   /* Split the file name. */
   if (((pcdfsi->cdi_flags & (CDI_ISVALID | CDI_ISROOT |
      CDI_ISCURRENT)) != CDI_ISVALID) || (iCurDirEnd == (USHORT) -1))
   {
      splitPath(szPath + 2, szDir, szName);
      idStart = pVolData->idRoot;
   } else {
      if (iCurDirEnd > strlen(szPath))
         iCurDirEnd = strlen(szPath);
      logMsg(L_DBG, "starting lookup for %s at curdir",
         szPath + iCurDirEnd);
      splitPath(szPath + iCurDirEnd, szDir, szName);
      idStart = (CryptedFileID) pcdfsd->data[0];
   }

   /* Find the directory. */
   cr = coreQueryIDFromPath(
      pVolData->pVolume, idStart,
      szDir, pidDir, 0);
   if (cr) return cr;

   /* Does the file appear in the directory? */
   return coreQueryIDFromPath(
      pVolData->pVolume, *pidDir,
      szName, pidFile, ppDirEntry);
}


CoreResult findFromCurDir2(VolData * pVolData, char * szPath,
   struct cdfsi * pcdfsi, CDFSD * pcdfsd, USHORT iCurDirEnd,
   CryptedFileID * pidFile, CryptedDirEntry * * ppDirEntry)
{
   CryptedFileID idStart;

   logMsg(L_DBG, "looking up: %s, curdir=%s, id=%08x, iCurDirEnd=%hd",
      szPath, pcdfsi->cdi_curdir, (CryptedFileID) pcdfsd->data[0],
      iCurDirEnd);

   *pidFile = 0;
   
   if (((pcdfsi->cdi_flags & (CDI_ISVALID | CDI_ISROOT |
      CDI_ISCURRENT)) != CDI_ISVALID) || (iCurDirEnd == (USHORT) -1))
   {
      szPath += 2;
      idStart = pVolData->idRoot;
   } else {
      if (iCurDirEnd > strlen(szPath))
         iCurDirEnd = strlen(szPath);
      logMsg(L_DBG, "starting lookup for %s at curdir",
         szPath + iCurDirEnd);
      szPath += iCurDirEnd;
      idStart = (CryptedFileID) pcdfsd->data[0];
   }

   /* Find the file. */
   return coreQueryIDFromPath(
      pVolData->pVolume, idStart,
      szPath, pidFile, ppDirEntry);
}
