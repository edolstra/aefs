/* aefsutil.c -- List directories, extract files, or dump entire
   directories from an AEFS file system.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: aefsutil.c,v 1.13 2002/01/14 21:33:14 eelco Exp $

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
#include <pwd.h>
#include <grp.h>

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
#define FL_VERYLONG     8
#define FL_FORCE       16
#define FL_VERBOSE     32
#define FL_RECURSIVE   64
#define FL_RECURSED  1024


static void printUsage(int status);


static void paramError()
{
   fprintf(stderr, "%s: missing or too many parameters\n",
      pszProgramName);
   printUsage(1);
}


int findPath(bool fTop, CryptedVolume * pVolume, CryptedFileID idStart,
   char * pszPath, CryptedFileID * pidFile, CryptedDirEntry * * ppEntry)
{
   CoreResult cr;

   if (!fTop || pszPath[0] == '/') {

      cr = coreQueryIDFromPath(
	 pVolume, 
	 idStart,
	 pszPath, pidFile, ppEntry);
      if (cr) {
	 fprintf(stderr, "%s: unable to lookup file: %s\n", 
	    pszProgramName, core2str(cr));
	 return 1;
      }

      if (ppEntry && *pidFile == idStart) {
         coreFreeDirEntries(*ppEntry);
         cr = coreAllocDirEntry("root", *pidFile, 0, ppEntry);
         assert(cr == CORERC_OK);
      }

   } else {

      if (sscanf(pszPath, "%lx", pidFile) != 1) {
	 fprintf(stderr, "%s: invalid path (must be path name or file ID)\n", 
	    pszProgramName);
	 return 1;
      }

      if (ppEntry) {
         cr = coreAllocDirEntry(pszPath, *pidFile, 0, ppEntry);
         assert(cr == CORERC_OK);
      }

   }

   return 0;
}


static int showInfo(SuperBlock * pSuperBlock, unsigned int flFlags)
{
   printf("\
    Version: %d.%d.%d\n\
    Root ID: %08lx\n\
  DOS label: \"%s\"\n\
Description: \"%s\"\n\
      Flags: %sdirty, %sencrypted-key\n\
Cipher type: %s-%d-%d (%s) in %s mode\n\
",
      (pSuperBlock->version >> 16) & 0xff,
      (pSuperBlock->version >> 8) & 0xff,
      pSuperBlock->version & 0xff,
      pSuperBlock->idRoot,
      pSuperBlock->szLabel,
      pSuperBlock->szDescription,
      pSuperBlock->flFlags & SBF_DIRTY ? "" : "not-",
      pSuperBlock->fEncryptedKey ? "" : "no-",
      pSuperBlock->pDataKey->pCipher->pszID,
      pSuperBlock->pDataKey->cbKey * 8,
      pSuperBlock->pDataKey->cbBlock * 8,
      pSuperBlock->pDataKey->pCipher->pszDescription,
      coreQueryVolumeParms(pSuperBlock->pVolume)->flCryptoFlags & CCRYPT_USE_CBC 
      ? "Cipher Block Chaining" : "Electronic Code Book"
      );
   return 0;
}


static int showFile(CryptedVolume * pVolume, 
   CryptedFileID id, char * pszPrefix, char * pszName, 
   unsigned int flFlags, unsigned int flDirFlags)
{
   CryptedFileInfo info;
   CoreResult cr;
   char bits[14], date[100];
   time_t t;
   struct tm * tm;
   struct passwd * pw;
   struct group * gr;
   char pwn[40], grn[40];

   if (!(flFlags & (FL_LONG | FL_VERYLONG))) {
      printf("%s%s\n", pszPrefix, pszName);
   } else {
      
      cr = coreQueryFileInfo(pVolume, id, &info);
      if (cr) {
         fprintf(stderr, "%s: unable to query file info about %s: %s\n", 
            pszProgramName, pszName, core2str(cr));
         return 1;
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
      bits[10] = info.flFlags & CFF_OS2S ? 'S' : '-';
      bits[11] = flDirFlags & CDF_HIDDEN ? 'H' : '-';
      bits[12] = info.flFlags & CFF_OS2A ? 'A' : '-';
      bits[13] = 0;

      /* !!! TODO: a way to display creation / access time */
      t = (time_t) info.timeWrite;
      tm = localtime(&t);
      strftime(date, sizeof(date), "%b %d %Y %H:%M:%S", tm);

      sprintf(pwn, "%-8d", info.uid);
      pw = getpwuid(info.uid);
      sprintf(grn, "%-8d", info.gid);
      gr = getgrgid(info.gid);
      
      if (flFlags & FL_LONG)
         printf("%s %-8s %-8s %10ld %s %s%s\n", 
            bits, pw ? pw->pw_name : pwn, gr ? gr->gr_name : grn,
            info.cbFileSize, date, pszPrefix, pszName);
      else 
         printf("%8lx %s%4d %-8s %-8s %10ld %5ld %s %s%s\n", 
            id, bits, info.cRefs, pw ? pw->pw_name : pwn, 
            gr ? gr->gr_name : grn,
            info.cbFileSize, info.cbEAs, date, pszPrefix, pszName);
   }

   return 0;
}


static bool isDir(CryptedVolume * pVolume, CryptedFileID id)
{
   CryptedFileInfo info;
   if (coreQueryFileInfo(pVolume, id, &info)) return false;
   return CFF_ISDIR(info.flFlags);
}


static int listDir(SuperBlock * pSuperBlock, CryptedFileID idFrom, 
   char * pszPrefix, char * pszPath, unsigned int flFlags, bool fTop)
{
   char szFull[_POSIX_PATH_MAX]; /* !!! stack usage! */
   CryptedVolume * pVolume = pSuperBlock->pVolume;
   CryptedDirEntry * pDir, * pFirst, * pCur;
   CryptedFileID idDir;
   CoreResult cr;
   int res = 0;
   bool fIsDir;
   
   if (findPath(fTop, pVolume, idFrom, pszPath, &idDir, &pDir)) return 1;

   fIsDir = isDir(pVolume, idDir);

   if (flFlags & FL_RECURSED && !fIsDir) return 0;

   if ((flFlags & FL_DIR) || !fIsDir) {
      res = showFile(pVolume, idDir, pszPrefix,
         pDir->pszName, flFlags, pDir->flFlags);
   } else {

      if (!(flFlags & FL_RECURSED))
         res |= showFile(pVolume, idDir, pszPrefix, ".", flFlags,
            pDir->flFlags);

      cr = coreQueryDirEntries(pVolume, idDir, &pFirst);
      if (cr) {
         coreFreeDirEntries(pFirst);
         fprintf(stderr, "%s: unable to read directory: %s\n", 
            pszProgramName, core2str(cr));
         res = 1;
      } else {
         for (pCur = pFirst; pCur; pCur = pCur->pNext) {
            res |= showFile(pVolume, pCur->idFile, pszPrefix,
               pCur->pszName, flFlags, pCur->flFlags);

            if (flFlags & FL_RECURSIVE) {
               if (snprintf(szFull, sizeof(szFull), "%s%s/",
                      pszPrefix, pCur->pszName) > sizeof(szFull))
               {
                  fprintf(stderr, "%s: path too long\n", pszProgramName);
                  continue;
               }
               res |= listDir(pSuperBlock, pCur->idFile, 
                  szFull, "", flFlags | FL_RECURSED, false);
            }

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
   char * pszFrom, char * pszTo, unsigned int flFlags, bool fTop)
{
   char szFull[_POSIX_PATH_MAX]; /* !!! stack usage! */
   CryptedDirEntry * pEntry, * pFirst, * pCur;
   CryptedFileID idFile;
   CryptedFileInfo info;
   int h, res = 0;
   struct utimbuf timebuf;
   CoreResult cr;

   if (findPath(fTop, pVolume, idFrom, 
          pszFrom, &idFile, &pEntry)) return 1;

   cr = coreQueryFileInfo(pVolume, idFile, &info);
   if (cr) {
      coreFreeDirEntries(pEntry);
      fprintf(stderr, "%s: unable to query file info: %s\n", 
         pszProgramName, core2str(cr));
      return 1;
   }

   if (snprintf(szFull, sizeof(szFull), "%s/%s",
      pszTo, pEntry->pszName) > sizeof(szFull))
   {
      coreFreeDirEntries(pEntry);
      fprintf(stderr, "%s: path too long\n", pszProgramName);
      return 1;
   }
   coreFreeDirEntries(pEntry);

   if (flFlags & FL_VERBOSE)
      fprintf(stderr, "%s\n", szFull);
      
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
            res |= dump(pVolume, idFile, pCur->pszName,
               szFull, flFlags, false);
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
#ifdef HAVE_CHOWN      
      if (getuid() == 0) {
         chown(szFull, info.uid, info.gid);
      }
#endif      
   }

   return res;
}


static int cat(SuperBlock * pSuperBlock, char * pszPath)
{
   CryptedVolume * pVolume = pSuperBlock->pVolume;
   CryptedFileID idFile;
   CryptedFileInfo info;
   CoreResult cr;

   if (findPath(true, pVolume, pSuperBlock->idRoot, pszPath, &idFile, 0)) return 1;

   cr = coreQueryFileInfo(pSuperBlock->pVolume, idFile, &info);
   if (cr) {
      fprintf(stderr, "%s: unable to query file info: %s\n", 
         pszProgramName, core2str(cr));
      return 1;
   }

   return copy(pSuperBlock->pVolume, 
      idFile, info.cbFileSize, STDOUT_FILENO);
}


static int doCommand(char * pszPassPhrase, char * pszBasePath, 
   char * pszCommand, int argc, char * * argv, unsigned int flFlags)
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

   cr = coreReadSuperBlock(szBasePath, pszPassPhrase, cipherTable, 
      &parms, &pSuperBlock);
   if (cr) {
      fprintf(stderr, "%s: unable to read superblock: %s\n", 
         pszProgramName, core2str(cr));
      if (!pSuperBlock || !(flFlags & FL_FORCE)) {
          if (pSuperBlock) coreDropSuperBlock(pSuperBlock);
          return 1;
      }
   }

   if (strcmp(pszCommand, "info") == 0) {
      if (argc != 0) paramError();
      res = showInfo(pSuperBlock, flFlags);
   } else if (strcmp(pszCommand, "ls") == 0) {
      if (argc != 1) paramError();
      res = listDir(pSuperBlock, pSuperBlock->idRoot, 
         "", argv[0], flFlags, true);
   } else if (strcmp(pszCommand, "dump") == 0) {
      if (argc != 1) paramError();
      res = dump(pSuperBlock->pVolume, pSuperBlock->idRoot, argv[0], 
         ".", flFlags, true);
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


static void printUsage(int status)
{
   if (status)
      fprintf(stderr,
         "\nTry `%s --help' for more information.\n",
         pszProgramName);
   else {
      printf("\
Usage: %s [OPTION]... AEFS-PATH COMMAND ...\n\
List directories on or extract files from the AEFS file system stored\n\
in AEFS-PATH.\n\
\n\
  -d, --directory    list directory entries instead of contents\n\
  -f, --force        continue in case of an unreadable superblock\n\
  -k, --key=KEY      use specified passphrase, do not ask\n\
  -l, --long         show detailed file information\n\
      --verylong     show very detailed file information\n\
  -p, --preserve     preserve permissions/ownerships when extracting\n\
  -r, --recursieve   (ls) list recursively\n\
  -v, --verbose      (dump) show what is happening\n\
      --help         display this help and exit\n\
      --version      output version information and exit\n\
\n\
COMMAND is one of the following:\n\
\n\
  info               show information about the file system\n\
  ls PATH            list directory contents\n\
  dump PATH          extract recursively to the current directory\n\
  cat PATH           extract file to standard output\n\
\n\
PATH must either be a fully qualified path name (i.e., starting with\n\
`/') or a hexadecimal number denoting a file ID (inode number).\n\
\n\
" STANDARD_KEY_HELP "\
\n\
The long listing displays the flags, ownership, file size, last\n\
modification date, and file name.  The very long listing displays the\n\
file ID (inode number), flags, reference count, ownership, file size,\n\
size of the extended attributes, last modification date, and file\n\
name.  The flag characters indicate the file type, permissions (read,\n\
write, and execute permission for the user, group, and others), and\n\
OS/2 system, hidden, and archive attributes.\n\
",
         pszProgramName);
   }
   exit(status);
}


int main(int argc, char * * argv)
{
   char * pszPassPhrase = 0, * pszBasePath, * pszCommand;
   char szPassPhrase[1024];
   int c, res;
   unsigned int flFlags = 0;

   struct option options[] = {
      { "help", no_argument, 0, 1 },
      { "version", no_argument, 0, 2 },
      { "key", required_argument, 0, 'k' },
      { "directory", no_argument, 0, 'd' },
      { "force", no_argument, 0, 'f' },
      { "long", no_argument, 0, 'l' },
      { "verylong", no_argument, 0, 3 },
      { "preserve", no_argument, 0, 'p' },
      { "recursive", no_argument, 0, 'r' },
      { "verbose", no_argument, 0, 'v' },
      { 0, 0, 0, 0 } 
   };

   pszProgramName = argv[0];

   while ((c = getopt_long(argc, argv, "k:dflprv", options, 0)) != EOF) {
      switch (c) {
         case 0:
            break;

         case 1: /* --help */
            printUsage(0);
            break;

         case 2: /* --version */
            printf("aefsutil - %s\n", AEFS_VERSION);
            exit(0);
            break;
            
         case 'k': /* --key */
            pszPassPhrase = optarg;
            break;

         case 'd': /* --directory */
            flFlags |= FL_DIR;
            break;

         case 'f': /* --force */
            flFlags |= FL_FORCE;
            break;

         case 'l': /* --long */
            flFlags |= FL_LONG;
            break;

         case 3: /* --verylong */
            flFlags |= FL_VERYLONG;
            break;

         case 'p': /* --preserve */
            flFlags |= FL_PRESERVE;
            break;

         case 'r': /* --recursive */
            flFlags |= FL_RECURSIVE;
            break;

         case 'v': /* --verbose */
            flFlags |= FL_VERBOSE;
            break;

         default:
            printUsage(1);
      }
   }

   if (optind > argc - 2) paramError();

   pszBasePath = argv[optind++];
   pszCommand = argv[optind++];

   /* Passphrase specified in the environment? */
   if (!pszPassPhrase) {
      pszPassPhrase = getenv("AEFS_PASSPHRASE");
   }

   /* Ask the user to enter the passphrase, if it wasn't specified
      with "-k". */
   if (!pszPassPhrase) {
      pszPassPhrase = szPassPhrase;
      if (readPhrase("passphrase: ", sizeof(szPassPhrase), szPassPhrase)) {
         fprintf(stderr, "%s: error reading passphrase\n", pszProgramName);
         return 0;
      }
   }

   res = doCommand(pszPassPhrase, pszBasePath, pszCommand,
      argc - optind, argv + optind, flFlags);

   memset(pszPassPhrase, 0, strlen(pszPassPhrase)); /* burn */

   return res;
}
