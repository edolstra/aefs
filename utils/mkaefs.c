/* mkaefs.c -- AEFS file system creation program.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: mkaefs.c,v 1.9 2001/09/23 13:30:25 eelco Exp $

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
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "getopt.h"
#include "sysdep.h"
#include "corefs.h"
#include "superblock.h"
#include "ciphertable.h"

#include "utilutils.h"


char * pszProgramName;


static Key * makeKey(char * pszCipher, char * pszKey)
{
   CoreResult cr;
   CipherResult cr2;
   char szKey[1024], szKey2[1024];
   octet abKey[MAX_KEY_SIZE];
   Cipher * pCipher;
   unsigned int cbBlock, cbKey;
   Key * pKey;

   if (!pszCipher) pszCipher = (*cipherTable)->pszID;
   
   /* Find the specified cipher. */
   pCipher = findCipher(cipherTable, pszCipher,
      &cbBlock, &cbKey);
   if (!pCipher) {
      fprintf(stderr, "%s: invalid cipher specification `%s' "
         "(use `--help' to see a list of known ciphers)\n",
         pszProgramName, pszCipher);
      return 0;
   }

   printf("%s: using algorithm %s-%d-%d\n", pszProgramName,
      pCipher->pszID, cbKey * 8, cbBlock * 8);

   /* Ask the use to enter the key, if it wasn't specified with "-k". */
   if (!pszKey) {
      pszKey = szKey;
   retry:      
      if (readKey("key: ", sizeof(szKey), szKey)) {
         fprintf(stderr, "%s: error reading key\n", pszProgramName);
         return 0;
      }
      if (readKey("key (again): ", sizeof(szKey2), szKey2)) {
         fprintf(stderr, "%s: error reading key\n", pszProgramName);
         return 0;
      }
      if (strcmp(szKey, szKey2) != 0) {
         fprintf(stderr, "%s: the keys do not match, please retry.\n",
            pszProgramName);
         goto retry;
      }
      memset(szKey2, 0, sizeof(szKey2)); /* burn */
   }

   /* Hash the key the user entered into the cbKey-bytes wide key
      expected by the cipher. */
   cr = coreHashKey(pszKey, abKey, cbKey);
   memset(szKey, 0, sizeof(szKey)); /* burn */
   if (cr) {
      fprintf(stderr, "%s: error hashing key: %s\n",
         pszProgramName, core2str(cr));
      return 0;
   }

#if 0   
   {
      int i;
      printf("real key: ");
      for (i = 0; i < cbKey; i++)
         printf("%02x", (int) abKey[i]);
      printf("\n");
   }
#endif   

   /* Construct a cipher instance. */
   cr2 = cryptCreateKey(pCipher, cbBlock, cbKey, abKey, &pKey);
   memset(abKey, 0, sizeof(abKey)); /* burn */
   if (cr2) {
      fprintf(stderr, "%s: cannot construct cipher `%s' "
         "(use `--help' to see a list of known ciphers)\n",
         pszProgramName, pszCipher);
      return 0;
   }

   return pKey;
}


static CoreResult makeRootDir(CryptedVolume * pVolume,
   CryptedFileID * pidRootDir)
{
   CoreResult cr;
   CryptedFileID idRootDir;
   CryptedFileInfo info;

   *pidRootDir = 0;

   /* Create a new directory. */
   memset(&info, 0, sizeof(info));
   info.flFlags = CFF_IFDIR | 0700; /* rwx for user */
   info.cRefs = 1;
   info.cbFileSize = 0;
   info.timeWrite = info.timeAccess = info.timeCreation = time(0);
   info.idParent = 0;
   /* uid and gid are set to 0 */
   cr = coreCreateBaseFile(pVolume, &info, &idRootDir);
   if (cr) return cr;

   *pidRootDir = idRootDir;

   return CORERC_OK;
}


int createISF(CryptedVolume * pVolume)
{
   CoreResult cr;
   
   cr = coreCreateFile(pVolume, INFOSECTORFILE_ID, 1);
   if (cr) {
      fprintf(stderr, "%s: unable to init info sector file: %s\n",
         pszProgramName, core2str(cr));
      return 1;
   }
   
   cr = coreInitISF(pVolume);
   if (cr) {
      fprintf(stderr, "%s: unable to init info sector file: %s\n",
         pszProgramName, core2str(cr));
      return 1;
   }

   return 0;
}


int initVolume(char * pszBasePath, Key * pKey,
   CryptedVolume * pVolume)
{
   CoreResult cr;
   CryptedFileID idRootDir;
   SuperBlock superblock;
   time_t now;
   
   /* Create the ISF. */
   if (createISF(pVolume)) return 1;
   
   /* Create the root directory. */
   cr = makeRootDir(pVolume, &idRootDir);
   if (cr) {
      fprintf(stderr, "%s: unable to create root directory: %s\n",
         pszProgramName, core2str(cr));
      return 1;
   }

   /* Create the superblock in-core. */
   superblock.pszBasePath = pszBasePath;
   superblock.pVolume = pVolume;
   superblock.pKey = pKey;
   superblock.flFlags = 0;
   superblock.idRoot = idRootDir;
   strcpy(superblock.szLabel, "AEFS");
   time(&now);
   strftime(superblock.szDescription,
      sizeof(superblock.szDescription),
      "Volume created on %a, %d %b %Y %H:%M:%S UTC",
      gmtime(&now));
   superblock.pSB2File = 0;

   /* Write the superblock. */
   cr = coreWriteSuperBlock(&superblock, 0);
   if (cr) {
      fprintf(stderr, "%s: unable to write the superblocks: %s\n",
         pszProgramName, core2str(cr));
      return 1;
   }

   return 0;
}



int createVolumeInPath(char * pszBasePath, Key * pKey,
   bool fUseCBC, bool fForce)
{
   CoreResult cr;
   int res;
   CryptedVolume * pVolume;
   char szBasePath[MAX_VOLUME_BASE_PATH_NAME], * p;
   CryptedVolumeParms parms;

   if (strlen(pszBasePath) >= sizeof(szBasePath) - 2) return 1;
   strcpy(szBasePath, pszBasePath);

   /* Remove trailing slashes (mkdir doesn't like them). */
   for (p = szBasePath + strlen(szBasePath) - 1;
        p >= szBasePath && ((*p == '/') || (*p == '\\'));
        p--)
      *p = 0;
   
   /* Create the base path. */
   if (mkdir(szBasePath, 0700) && (errno != EEXIST || !fForce)) {
      fprintf(stderr, "%s: creating directory: %s\n", pszProgramName,
         strerror(errno));
      return 1;
   }

   /* Append a slash, because that's what corefs wants. */
   strcat(szBasePath, "/");

   /* Create a CryptedVolume structure. */
   coreSetDefVolumeParms(&parms);
   if (fUseCBC) 
      parms.flCryptoFlags |= CCRYPT_USE_CBC;
   else
      parms.flCryptoFlags &= ~CCRYPT_USE_CBC;
   parms.csISFGrow = 1;
/*    parms.acbitsDivision[0] = 8; */
/*    parms.acbitsDivision[1] = 0; */
   
   cr = coreAccessVolume(szBasePath, pKey, &parms, &pVolume);
   if (cr) {
      fprintf(stderr, "%s: unable to create superblock: %s\n",
         pszProgramName, core2str(cr));
      return 1;
   }

   /* Initialize the volume (i.e. create a root directory and write
      the superblocks. */
   res = initVolume(szBasePath, pKey, pVolume);
   
   /* Drop the volume, commit all writes. */
   cr = coreDropVolume(pVolume);
   if (cr) {
      fprintf(stderr, "%s: unable to commit file system: %s\n",
         pszProgramName, core2str(cr));
      res = 1;
   }

   return res;
}


static void printUsage(int status)
{
   Cipher * * papCipher;
   Cipher * pCipher;
   CipherSize * pSize;
   
   if (status)
      fprintf(stderr,
         "\nTry `%s --help' for more information.\n",
         pszProgramName);
   else {
      
      printf("\
Usage: %s [OPTION]... PATH\n\
Create an AEFS file system in directory PATH.\n\
\n\
      --force          force use of specified directory, even if it\n\
                        already exists\n\
  -k, --key=KEY        use specified key, do not ask\n\
  -c, --cipher=CIPHER  use CIPHER (see list below)\n\
      --no-cbc         do not use CBC mode (only for debugging)\n\
      --help           display this help and exit\n\
      --version        output version information and exit\n\
\n\
If the key is not specified on the command-line, the user is asked\n\
to enter the key interactively.\n\
\n\
The following table specifies the available ciphers (in\n\
ciphername-keysize-blocksize format, where the sizes are in number of\n\
bits).  The first entry in the table is the default cipher.\n\
",
         pszProgramName);
      
      for (papCipher = cipherTable; *papCipher; papCipher++) {
         pCipher = *papCipher;
         printf("\n  %s:\n", pCipher->pszDescription);
         for (pSize = pCipher->paSizes;
              pSize->cbBlock;
              pSize++)
            printf("    %s-%d-%d\n",
               pCipher->pszID,
               pSize->cbKey * 8,
               pSize->cbBlock * 8);
      }
         
   }
   exit(status);
}


int main(int argc, char * * argv)
{
   bool fUseCBC = true;
   bool fForce = false;
   int res;
   Key * pKey;
   int c;
   char * pszKey = 0, * pszCipher = 0, * pszBasePath;

   struct option const options[] =
   {
      { "help", no_argument, 0, 1 },
      { "version", no_argument, 0, 2 },
      { "key", required_argument, 0, 'k' },
      { "cipher", required_argument, 0, 'c' },
      { "no-cbc", no_argument, 0, 3 },
      { "force", no_argument, 0, 4 },
      { 0, 0, 0, 0 } 
   };

   sysInitPRNG();

   /* Parse the arguments. */
   
   pszProgramName = argv[0];

   while ((c = getopt_long(argc, argv, "k:c:", options, 0)) != EOF) {
      switch (c) {
         case 0:
            break;

         case 1: /* --help */
            printUsage(0);
            break;

         case 2: /* --version */
            printf("mkaefs - %s\n", AEFS_VERSION);
            exit(0);
            break;

         case 'k': /* --key */
            pszKey = optarg;
            break;

         case 'c': /* --cipher */
            pszCipher = optarg;
            break;

         case 3: /* --no-cbc */
            fUseCBC = false;
            break;

         case 4: /* --force */
            fForce = true;
            break;

         default:
            printUsage(1);
      }
   }

   if (optind != argc - 1) {
      fprintf(stderr, "%s: missing or too many parameters\n", pszProgramName);
      printUsage(1);
   }

   pszBasePath = argv[optind++];

   /* Construct a cipher instance. */
   pKey = makeKey(pszCipher, pszKey);
   if (pszKey) memset(pszKey, 0, strlen(pszKey)); /* burn */
   if (!pKey) return 1;

   /* Make the volume. */
   res = createVolumeInPath(pszBasePath, pKey, fUseCBC, fForce);

   /* Clean up. */
   cryptDestroyKey(pKey);

   return res;
}
