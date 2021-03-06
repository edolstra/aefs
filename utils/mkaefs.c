/* mkaefs.c -- AEFS file system creation program.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

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
   info.uid = getuid();
   info.gid = getgid();
   cr = coreCreateBaseFile(pVolume, &info, &idRootDir);
   if (cr) return cr;

   *pidRootDir = idRootDir;

   return CORERC_OK;
}


static int createISF(CryptedVolume * pVolume)
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


static int initVolume(char * pszBasePath, octet * pabDataKey, 
   Key * pDataKey, CryptedVolume * pVolume, char * pszPassPhrase,
   bool fDataKey)
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
   strcpy(superblock.szBasePath, pszBasePath);
   superblock.pVolume = pVolume;
   superblock.pDataKey = pDataKey;
   superblock.flFlags = 0;
   superblock.idRoot = idRootDir;
   superblock.fEncryptedKey = fDataKey;
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

   /* Write the encrypted data key. */
   if (fDataKey) {
      
      memcpy(superblock.abDataKey, pabDataKey, MAX_KEY_SIZE);
      cr = coreWriteDataKey(&superblock, pszPassPhrase);
      memset(superblock.abDataKey, 0, MAX_KEY_SIZE);
      if (cr) {
	 fprintf(stderr, "%s: unable to write the data key: %s\n",
	    pszProgramName, core2str(cr));
	 return 1;
      }

   }

   return 0;
}


/* Round x up to a multiple of y. */
#define ROUND_UP(x, y) ((x) ? (((x) - 1) / (y) + 1) * (y) : 0)


static int createVolumeInPath(char * pszBasePath, 
   char * pszCipher, char * pszPassPhrase, bool fUseCBC, bool fDataKey)
{
   CoreResult cr;
   CipherResult cr2;
   Cipher * pCipher;
   unsigned int cbBlock, cbKey;
   char szPassPhrase[1024], szPassPhrase2[1024];
   int res;
   CryptedVolume * pVolume;
   char szBasePath[MAX_VOLUME_BASE_PATH_NAME], * p;
   CryptedVolumeParms parms;
   octet abDataKey[MAX_KEY_SIZE];
   Key * pDataKey;

   if (strlen(pszBasePath) + 1 >= MAX_VOLUME_BASE_PATH_NAME) {
      fprintf(stderr, "%s: base path too long\n", pszProgramName);
      return 1;
   }
   strcpy(szBasePath, pszBasePath);

   if (!pszCipher) pszCipher = cipherTable[0]->pszID;
   
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

   /* Ask the user to enter the passphrase, if it wasn't specified
      with "-k". */
   if (!pszPassPhrase) {
      pszPassPhrase = szPassPhrase;
   retry:      
      if (readPhrase("passphrase: ", sizeof(szPassPhrase), szPassPhrase)) {
         fprintf(stderr, "%s: error reading passphrase\n", pszProgramName);
         return 0;
      }
      if (readPhrase("passphrase (again): ", sizeof(szPassPhrase2), szPassPhrase2)) {
         fprintf(stderr, "%s: error reading passphrase\n", pszProgramName);
         return 0;
      }
      if (strcmp(szPassPhrase, szPassPhrase2) != 0) {
         fprintf(stderr, "%s: the passphrases do not match, please retry.\n",
            pszProgramName);
         goto retry;
      }
      memset(szPassPhrase2, 0, sizeof(szPassPhrase2)); /* burn */
   }

   /* Remove trailing slashes (mkdir doesn't like them). */
   for (p = szBasePath + strlen(szBasePath) - 1;
        p >= szBasePath && ((*p == '/') || (*p == '\\'));
        p--)
      *p = 0;
   
   /* Create the base path. */
   if (mkdir(szBasePath, 0700)) {
      fprintf(stderr, "%s: creating directory: %s\n", pszProgramName,
         strerror(errno));
      return 1;
   }

   /* Determine the volume parameters. */
   coreSetDefVolumeParms(&parms);
   if (fUseCBC) 
      parms.flCryptoFlags |= CCRYPT_USE_CBC;
   else
      parms.flCryptoFlags &= ~CCRYPT_USE_CBC;
   parms.csISFGrow = 1;

   /* Append a slash, because that's what corefs wants. */
   strcat(szBasePath, "/");

   /* Terminology: 
      - passphrase: a variable-length string given by the user.
      - pass key: the pass phrase hashed using coreHashKey().
      - data key: a randomly generated key used to encrypt the
      data on the file system.
      - encrypted data key: the contents of the file basepath/KEY,
      being the data key encrypted with the pass key.  If
      basepath/KEY does not exist, then data key == pass key.
      The ciphers used in encrypting the data key and the volume
      data are the same (simpler that way; otherwise we would have
      to have two flags to specify the ciphers).
   */

   if (fDataKey) {

      /* Generate the data key. */
      sysGetRandomBits(cbKey * 8, abDataKey);

   } else {

      /* Hash the key the user entered into the cbKey-bytes wide key
	 expected by the cipher. */
      cr = coreHashPhrase(pszPassPhrase, abDataKey, cbKey);
      memset(szPassPhrase, 0, sizeof(szPassPhrase)); /* burn */
      if (cr) {
	 fprintf(stderr, "%s: error hashing passphrase: %s\n",
	    pszProgramName, core2str(cr));
	 return 0;
      }

   }

   printKey("data key", cbKey, abDataKey);

   /* Construct a cipher instance. */
   cr2 = cryptCreateKey(pCipher, cbBlock, cbKey, abDataKey, &pDataKey);
   if (cr2) {
      fprintf(stderr, "%s: cannot construct cipher instance\n", 
	 pszProgramName);
      return 0;
   }

   /* Create a CryptedVolume structure. */
   cr = coreAccessVolume(szBasePath, pDataKey, &parms, &pVolume);
   if (cr) {
      fprintf(stderr, "%s: unable to create superblock: %s\n",
         pszProgramName, core2str(cr));
      return 1;
   }

   /* Initialize the volume (i.e. create a root directory and write
      the superblocks. */
   res = initVolume(szBasePath, abDataKey, 
      pDataKey, pVolume, pszPassPhrase, fDataKey);
   memset(abDataKey, 0, sizeof(abDataKey)); /* burn */
   
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
  -k, --key=KEY        use specified passphrase, do not ask\n\
  -c, --cipher=CIPHER  use CIPHER (see list below)\n\
      --no-cbc         do not use CBC mode (only for debugging)\n\
      --no-random-key  do not generate a random data key (compatible\n\
                        with older versions of AEFS)\n\
      --help           display this help and exit\n\
      --version        output version information and exit\n\
\n\
" STANDARD_KEY_HELP "\
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
   bool fUseCBC = true, fDataKey = true;
   int res;
   int c;
   char * pszPassPhrase = 0, * pszCipher = 0, * pszBasePath;

   struct option const options[] =
   {
      { "help", no_argument, 0, 1 },
      { "version", no_argument, 0, 2 },
      { "key", required_argument, 0, 'k' },
      { "cipher", required_argument, 0, 'c' },
      { "no-cbc", no_argument, 0, 3 },
      { "no-random-key", no_argument, 0, 4 },
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
            pszPassPhrase = optarg;
            break;

         case 'c': /* --cipher */
            pszCipher = optarg;
            break;

         case 3: /* --no-cbc */
            fUseCBC = false;
            break;

         case 4: /* --no-random-key */
            fDataKey = false;
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

   /* Passphrase specified in the environment? */
   if (!pszPassPhrase) {
      pszPassPhrase = getenv("AEFS_PASSPHRASE");
   }

   /* Make the volume. */
   res = createVolumeInPath(pszBasePath, pszCipher, pszPassPhrase, 
      fUseCBC, fDataKey);
   if (pszPassPhrase) memset(pszPassPhrase, 0, strlen(pszPassPhrase)); /* burn */

   return res;
}
