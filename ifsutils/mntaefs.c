/* mntaefs.c -- AEFS mount program.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: mntaefs.c,v 1.5 2001/09/23 13:30:16 eelco Exp $

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
#include <process.h>
#include <string.h>
#include <ctype.h>

#include <os2.h>

#include "getopt.h"

#include "aefsdint.h"
#include "cipher.h"
#include "utilutils.h"
#include "aefsck.h"


char * pszProgramName;


static void printUsage(int status)
{
   if (status)
      fprintf(stderr,
         "\nTry `%s --help' for more information.\n",
         pszProgramName);
   else {
      printf("\
Usage: %s [OPTION]... DRIVE-LETTER: AEFS-PATH\n\
Mount the AEFS volume stored in AEFS-PATH onto DRIVE-LETTER.\n\
\n\
  -f, --force        force mount of dirty volume\n\
  -k, --key=KEY      use specified key, do not ask\n\
  -n, --nocheck      do not check dirty volume\n\
  -r, --readonly     mount read-only\n\
      --help         display this help and exit\n\
      --version      output version information and exit\n\
\n\
If the key is not specified on the command-line, the user is asked\n\
to enter the key.\n\
\n\
If the volume is dirty, mntaefs will by default invoke aefsck to\n\
check for and fix errors on the volume.  aefsck will be invoked\n\
with switches `--fix' and possibly `--key=<key>' if `-k' was an\n\
argument to mntaefs.\n\
\n\
Examples:\n\
  Mount the volume in `c:\\secret' onto drive X:\n\
    mntaefs x: c:\\secret\n\
",
         pszProgramName);
   }
   exit(status);
}


int main(int argc, char * * argv)
{
   bool fForceMount = false;
   bool fReadOnly = false;
   bool fAutoCheck = true;
   char szKey[1024], * pszOrigKey = 0;
   int c, r;
   AEFS_ATTACH attachparms;
   APIRET rc;
   char * pszKey = 0, * pszDrive, * pszBasePath;

   struct option const options[] = {
      { "help", no_argument, 0, 1 },
      { "version", no_argument, 0, 2 },
      { "key", required_argument, 0, 'k' },
      { "force", no_argument, 0, 'f' },
      { "readonly", no_argument, 0, 'r' },
      { "nocheck", no_argument, 0, 'n' },
      { 0, 0, 0, 0 } 
   };      

   /* Parse the arguments. */
   
   pszProgramName = argv[0];

   while ((c = getopt_long(argc, argv, "fk:nr", options, 0)) != EOF) {
      switch (c) {
         case 0:
            break;

         case 1: /* --help */
            printUsage(0);
            break;

         case 2: /* --version */
            printf("mntaefs - %s\n", AEFS_VERSION);
            exit(0);
            break;

         case 'k': /* --key */
            pszKey = pszOrigKey = optarg;
            break;

         case 'f': /* --force */
            fForceMount = true;
            break;

         case 'r': /* --readonly */
            fReadOnly = true;
            break;

         case 'n': /* --nocheck */
            fAutoCheck = false;
            break;

         default:
            printUsage(1);
      }
   }

   if (optind != argc - 2) {
      fprintf(stderr, "%s: missing or too many parameters\n", pszProgramName);
      printUsage(1);
   }

   pszDrive = argv[optind++];
   pszBasePath = argv[optind++];

   memset(&attachparms, 0, sizeof(attachparms));
   if (fForceMount) attachparms.flFlags |= AP_MOUNTDIRTY;
   if (fReadOnly) attachparms.flFlags |= AP_READONLY;

   /* Drive okay? */
   if ((strlen(pszDrive) != 2) ||
       (!isalpha((int) pszDrive[0])) ||
       (pszDrive[1] != ':'))
   {
      fprintf(stderr, "%s: drive specification is incorrect\n",
         pszProgramName);
      return 1;
   }

   /* Does the base path fit? */
   if (strlen(pszBasePath) >= sizeof(attachparms.szBasePath)) {
      fprintf(stderr, "%s: base path name is too long\n",
         pszProgramName);
      return 1;
   }
   strcpy(attachparms.szBasePath, pszBasePath);

   /* Expand the given base path.  (The daemon does not accept
      relative path names). */
   if (_abspath(attachparms.szBasePath, attachparms.szBasePath,
      sizeof(attachparms.szBasePath)))
   {
      fprintf(stderr, "%s: cannot expand path\n", pszProgramName);
      return 1;
   }

   /* Ask the use to enter the key, if it wasn't specified with "-k". */
   if (!pszKey) {
      pszKey = szKey;
      if (readKey("key: ", sizeof(szKey), szKey)) {
         fprintf(stderr, "%s: error reading key\n", pszProgramName);
         return 1;
      }
   }

   /* Does the key fit? */
   if (strlen(pszKey) >= sizeof(attachparms.szKey)) {
      fprintf(stderr, "%s: key is too long\n",
         pszProgramName);
      return 1;
   }
   strcpy(attachparms.szKey, pszKey);
   memset(szKey, 0, sizeof(szKey)); /* burn */

   /* Send the attachment request to the FSD. */
retry:
   rc = DosFSAttach(
      (PSZ) pszDrive,
      (PSZ) AEFS_IFS_NAME,
      &attachparms,
      sizeof(attachparms),
      FS_ATTACH);
   if (rc) {

      if (rc == ERROR_AEFS_DIRTY) {

         if (fAutoCheck && !fReadOnly) {
            printf("%s: the volume is dirty, starting aefsck...\n",
               pszProgramName);
            if (pszOrigKey)
               r = spawnl(P_WAIT, "aefsck.exe", "aefsck.exe",
                  "--fix", "--key", pszOrigKey, pszBasePath, (char *) 0);
            else
               r = spawnl(P_WAIT, "aefsck.exe", "aefsck.exe",
                  "--fix", pszBasePath, (char *) 0);

            if (r == -1) {
               printf("%s: aefsck.exe: %s\n", pszProgramName,
                  strerror(errno));
               return 1;
            } else if (r & (AEFSCK_NOTFIXED | AEFSCK_ABORT |
               AEFSCK_FAIL)) {
               printf(
                  "%s: aefsck.exe failed, will not mount, rc = %d\n",
                  pszProgramName, r);
               return 1;
            } else {
               printf("%s: volume cleaned, retrying...\n",
                  pszProgramName);
               fAutoCheck = false;
               goto retry;
            }
            
         } else {
            printf(
               "%s: the volume is dirty; use `-f' to force mount\n",
               pszProgramName);
            return 1;
         }
         
      } else {
         fprintf(stderr, "%s: error mounting AEFS volume, rc = %ld\n",
            pszProgramName, rc);
         return 1;
      }
      
   }

   return 0;
}
