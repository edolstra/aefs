/* aefsutil.c -- 
   Copyright (C) 2001 Eelco Dolstra (edolstra@students.cs.uu.nl).

   $Id: aefsutil.c,v 1.1 2001/01/02 13:29:08 eelco Exp $

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
#include <assert.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <utime.h>
#include <errno.h>

#include "getopt.h"
#include "corefs.h"
#include "coreutils.h"
#include "superblock.h"
#include "ciphertable.h"
#include "utilutils.h"


char * pszProgramName;


#define FL_DIR          1
#define FL_LONG         2
#define FL_PRESERVE     4


static void printUsage(int status)
{
   if (status)
      fprintf(stderr,
         "\nTry `%s --help' for more information.\n",
         pszProgramName);
   else {
      printf("!!!\n");
   }
   exit(status);
}


static void paramError()
{
   fprintf(stderr, "%s: missing or too many parameters\n",
      pszProgramName);
   printUsage(1);
}


static int showFile(CryptedVolume * pVolume, 
   CryptedFileID id, char * pszName, int flFlags)
{
   CryptedFileInfo info;
   CoreResult cr;
   char bits[12], date[100];
   time_t t;
   struct tm * tm;

   if (!(flFlags & FL_LONG)) {
      printf("%s\n", pszName);
   } else {
      
      cr = coreQueryFileInfo(pVolume, id, &info);
      if (cr) {
         fprintf(stderr, "%s: unable to query file info about %s: %s\n", 
            pszProgramName, pszName, core2str(cr));
         return 0;
      }

      switch (info.flFlags & CFF_IFMT) {
         case CFF_IFSOCK: bits[0] = 's'; break;
         case CFF_IFLNK: bits[0] = 'l'; break;
         case CFF_IFREG: bits[0] = '-'; break;
         case CFF_IFBLK: bits[0] = 'b'; break;
         case CFF_IFDIR: bits[0] = 'd'; break;
         case CFF_IFCHR: bits[0] = 'c'; break;
         case CFF_IFIFO: bits[0] = 'p'; break;
         default: bits[0] = '?';
      }
      bits[1] = info.flFlags & CFF_IRUSR ? 'r' : '-';
      bits[2] = info.flFlags & CFF_IWUSR ? 'w' : '-';
      bits[3] = info.flFlags & CFF_IXUSR ? 'x' : '-';
      bits[4] = info.flFlags & CFF_IRGRP ? 'r' : '-';
      bits[5] = info.flFlags & CFF_IWGRP ? 'w' : '-';
      bits[6] = info.flFlags & CFF_IXGRP ? 'x' : '-';
      bits[7] = info.flFlags & CFF_IROTH ? 'r' : '-';
      bits[8] = info.flFlags & CFF_IWOTH ? 'w' : '-';
      bits[9] = info.flFlags & CFF_IXOTH ? 'x' : '-';
      if (info.flFlags & CFF_ISUID) bits[3] = 's';
      if (info.flFlags & CFF_ISGID) bits[6] = 's';
      if (info.flFlags & CFF_ISVTX) bits[9] = 't';
      bits[10] = 0;

      t = (time_t) info.timeWrite;
      tm = localtime(&t);
      strftime(date, sizeof(date), "%b %d %Y %H:%M:%S", tm);

      printf("%8lx %s %10ld  %s %s\n", 
         id, bits, info.cbFileSize, date, pszName);
   }

   return 0;
}


static bool isDir(CryptedVolume * pVolume, CryptedFileID id)
{
   CryptedFileInfo info;
   if (coreQueryFileInfo(pVolume, id, &info)) return false;
   return CFF_ISDIR(info.flFlags);
}


static int listDir(SuperBlock * pSuperBlock, char * pszPath, 
   int flFlags)
{
   CryptedDirEntry * pDir, * pFirst, * pCur;
   CryptedFileID idDir;
   CoreResult cr;
   int res = 0;

   cr = coreQueryIDFromPath(
      pSuperBlock->pVolume, 
      pSuperBlock->idRoot,
      pszPath, &idDir, &pDir);
   if (cr) {
      fprintf(stderr, "%s: unable to lookup file: %s\n", 
         pszProgramName, core2str(cr));
      return 1;
   }

   if ((flFlags & FL_DIR) || !isDir(pSuperBlock->pVolume, idDir)) {
      res = showFile(pSuperBlock->pVolume, idDir,
         (char *) pDir->pabName, flFlags);
   } else {

      res |= showFile(pSuperBlock->pVolume, idDir, ".", flFlags);

      cr = coreQueryDirEntries(pSuperBlock->pVolume, idDir, &pFirst);
      if (cr) {
         coreFreeDirEntries(pFirst);
         fprintf(stderr, "%s: unable to read directory: %s\n", 
            pszProgramName, core2str(cr));
         res = 1;
      } else {
         for (pCur = pFirst; pCur; pCur = pCur->pNext) {
            res |= showFile(pSuperBlock->pVolume, pCur->idFile,
               (char *) pCur->pabName, flFlags);
         }
      }

      coreFreeDirEntries(pFirst);
   }

   coreFreeDirEntries(pDir);

   return res;
}


static int copy(CryptedVolume * pVolume, CryptedFileID idFile, 
   CryptedFilePos len, int h)
{
   char buffer[32768];
   CryptedFilePos pos, left, n, read;
   CoreResult cr;

   left = len; pos = 0;
   while (left) {
      n = sizeof(buffer); if (n > left) n = left;

      cr = coreReadFromFile(pVolume, idFile, pos, n,
         (octet *) buffer, &read);
      if (cr) {
         close(h);
         fprintf(stderr, "%s: cannot read from file: %s\n", 
            pszProgramName, core2str(cr));
         return 1;
      }

      if (write(h, buffer, read) == -1) {
         close(h);
         fprintf(stderr, "%s: cannot write to file: %s\n", 
            pszProgramName, strerror(errno));
         return 1;
      }
         
      left -= n; pos += n;
   }

   return 0;
}


static int dump(CryptedVolume * pVolume, CryptedFileID idFrom, 
   char * pszFrom, char * pszTo, int flFlags)
{
   char szFull[PATH_MAX];
   CryptedDirEntry * pEntry, * pFirst, * pCur;
   CryptedFileID idFile;
   CryptedFileInfo info;
   int h, res = 0;
   struct utimbuf timebuf;
   CoreResult cr;

   cr = coreQueryIDFromPath(
      pVolume, idFrom,
      pszFrom, &idFile, &pEntry);
   if (cr) {
      coreFreeDirEntries(pEntry);
      fprintf(stderr, "%s: unable to lookup file: %s\n", 
         pszProgramName, core2str(cr));
      return 1;
   }

   cr = coreQueryFileInfo(pVolume, idFile, &info);
   if (cr) {
      coreFreeDirEntries(pEntry);
      fprintf(stderr, "%s: unable to query file info: %s\n", 
         pszProgramName, core2str(cr));
      return 1;
   }

   if (snprintf(szFull, sizeof(szFull), "%s/%s",
      pszTo, (char *) pEntry->pabName) > sizeof(szFull))
   {
      coreFreeDirEntries(pEntry);
      fprintf(stderr, "%s: path too long\n", pszProgramName);
      return 1;
   }
   coreFreeDirEntries(pEntry);
      
   if (CFF_ISDIR(info.flFlags)) {

      if (mkdir(szFull, 0700) == -1) {
         fprintf(stderr, "%s: unable to create directory: %s\n", 
            pszProgramName, strerror(errno));
         return 1;
      }
      
      cr = coreQueryDirEntries(pVolume, idFile, &pFirst);
      if (cr) {
         coreFreeDirEntries(pFirst);
         fprintf(stderr, "%s: unable to read directory: %s\n", 
            pszProgramName, core2str(cr));
         return 1;
      } else {
         for (pCur = pFirst; pCur; pCur = pCur->pNext) {
            res |= dump(pVolume, idFile, (char *) pCur->pabName,
               szFull, flFlags);
         }
      }

   } else if (CFF_ISREG(info.flFlags)) {

      h = open(szFull, O_WRONLY | O_CREAT | O_EXCL, 0600);
      if (h == -1) {
         fprintf(stderr, "%s: cannot create file: %s\n", 
            pszProgramName, strerror(errno));
         return 1;
      }

      if (copy(pVolume, idFile, info.cbFileSize, h)) {
         close(h);
         return 1;
      }

      close(h);

   } else {
      fprintf(stderr, "%s: cannot yet deal with file type of %s\n", 
         pszProgramName, pszFrom);
      return 1;
   }

   if (flFlags & FL_PRESERVE) {
      chmod(szFull, info.flFlags & 0777);
      timebuf.actime = info.timeAccess;
      timebuf.modtime = info.timeWrite;
      utime(szFull, &timebuf);
      if (getuid() == 0) {
         chown(szFull, info.uid, info.gid);
      }
   }

   return res;
}


static int cat(SuperBlock * pSuperBlock, char * pszPath)
{
   CryptedFileID idFile;
   CryptedFileInfo info;
   CoreResult cr;

   cr = coreQueryIDFromPath(
      pSuperBlock->pVolume, 
      pSuperBlock->idRoot,
      pszPath, &idFile, 0);
   if (cr) {
      fprintf(stderr, "%s: unable to lookup file: %s\n", 
         pszProgramName, core2str(cr));
      return 1;
   }

   cr = coreQueryFileInfo(pSuperBlock->pVolume, idFile, &info);
   if (cr) {
      fprintf(stderr, "%s: unable to query file info: %s\n", 
         pszProgramName, core2str(cr));
      return 1;
   }

   return copy(pSuperBlock->pVolume, 
      idFile, info.cbFileSize, STDOUT_FILENO);
}


static int doCommand(char * pszKey, char * pszBasePath, 
   char * pszCommand, int argc, char * * argv, int flFlags)
{
   char szBasePath[1024];
   CryptedVolumeParms parms;
   SuperBlock * pSuperBlock;
   CoreResult cr;
   int res = 0;

   /* Append a slash, if necessary. */
   assert(strlen(pszBasePath) < sizeof(szBasePath) - 1);
   strcpy(szBasePath, pszBasePath);
   if (!IS_PATH_SEPARATOR(szBasePath[strlen(szBasePath) - 1]))
      strcat(szBasePath, "/");

   coreSetDefVolumeParms(&parms);
   parms.fReadOnly = true;

   cr = coreReadSuperBlock(szBasePath, pszKey, cipherTable, 
      &parms, &pSuperBlock);
   if (cr) {
      if (pSuperBlock) coreDropSuperBlock(pSuperBlock);
      fprintf(stderr, "%s: unable to read superblock: %s\n", 
         pszProgramName, core2str(cr));
      return 1;
   }

   if (strcmp(pszCommand, "ls") == 0) 
   {
      if (argc != 1) paramError();
      res = listDir(pSuperBlock, argv[0], flFlags);
   } else if (strcmp(pszCommand, "dump") == 0) {
      if (argc != 1) paramError();
      res = dump(pSuperBlock->pVolume, pSuperBlock->idRoot, argv[0], 
         ".", flFlags);
   } else if (strcmp(pszCommand, "cat") == 0) {
      if (argc != 1) paramError();
      res = cat(pSuperBlock, argv[0]);
   } else {
      fprintf(stderr, "%s: unknown command: %s\n", 
         pszProgramName, pszCommand);
      res = 1;
   }

   coreDropSuperBlock(pSuperBlock);

   return res;
}


int main(int argc, char * * argv)
{
   char * pszKey = 0, * pszBasePath, * pszCommand;
   char szKey[1024];
   int c, res;
   int flFlags = 0;

   struct option options[] = {
      { "help", no_argument, 0, 1 },
      { "version", no_argument, 0, 2 },
      { "key", required_argument, 0, 'k' },
      { "directory", no_argument, 0, 'd' },
      { "long", no_argument, 0, 'l' },
      { "preserve", no_argument, 0, 'p' },
      { 0, 0, 0, 0 } 
   };

   pszProgramName = argv[0];

   while ((c = getopt_long(argc, argv, "k:dlp", options, 0)) != EOF) {
      switch (c) {
         case 0:
            break;

         case 1: /* --help */
            printUsage(0);
            break;

         case 2: /* --version */
            printf("aefsdump - %s\n", AEFS_VERSION);
            exit(0);
            break;
            
         case 'k': /* --key */
            pszKey = optarg;
            break;

         case 'd': /* --directory */
            flFlags |= FL_DIR;
            break;

         case 'l': /* --long */
            flFlags |= FL_LONG;
            break;

         case 'p': /* --preserve */
            flFlags |= FL_PRESERVE;
            break;

         default:
            printUsage(1);
      }
   }

   if (optind > argc - 2) paramError();

   pszBasePath = argv[optind++];
   pszCommand = argv[optind++];

   /* Ask the use to enter the key, if it wasn't specified with "-k". */
   if (!pszKey) {
      pszKey = szKey;
      if (readKey("key: ", sizeof(szKey), szKey)) {
         fprintf(stderr, "%s: error reading key\n", pszProgramName);
         return 0;
      }
   }

   res = doCommand(pszKey, pszBasePath, pszCommand,
      argc - optind, argv + optind, flFlags);

   memset(pszKey, 0, strlen(pszKey)); /* burn */

   return res;
}
