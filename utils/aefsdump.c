/* aefsdump.c -- Off-line data extraction.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: aefsdump.c,v 1.7 2001/09/23 13:30:25 eelco Exp $

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
#include <assert.h>
#include <sys/types.h>

#include "getopt.h"
#include "corefs.h"
#include "superblock.h"
#include "ciphertable.h"
#include "utilutils.h"


char * pszProgramName;


static void printUsage(int status)
{
   if (status)
      fprintf(stderr,
         "\nTry `%s --help' for more information.\n",
         pszProgramName);
   else {
      printf("\
Usage: %s [OPTION]... FILE...\n\
Decrypt encrypted storage files to stdout.\n\
\n\
  -k, --key=KEY        use specified key, do not ask\n\
  -c, --cipher=CIPHER  use CIPHER (see `mkaefs --help' for a list)\n\
      --no-cbc         do not use CBC mode (only for debugging)\n\
      --help           display this help and exit\n\
      --version        output version information and exit\n\
\n\
Specify `-' to read from standard input.\n\
Note: if the storage file is piped in through stdin, you should use\n\
`-k', since the key would otherwise be read from stdin as well.\n\
",
         pszProgramName);
   }
   exit(status);
}


int main(int argc, char * * argv)
{
   CoreResult cr;
   CipherResult cr2;
   
   char * pszKey = 0, * pszCipher = 0;
   bool fUseCBC = true;
   char szKey[1024];
   octet abKey[MAX_KEY_SIZE];
   Cipher * pCipher;
   unsigned int cbBlock, cbKey;
   Key * pKey;
   
   char * name;
   bool isstdin;
   FILE * file;
   octet abData[SECTOR_SIZE];
   CryptedSectorData data;
   unsigned int i;
   ssize_t r, w;
   
   int c;
   
   struct option options[] = {
      { "help", no_argument, 0, 1 },
      { "version", no_argument, 0, 2 },
      { "key", required_argument, 0, 'k' },
      { "cipher", required_argument, 0, 'c' },
      { "no-cbc", no_argument, 0, 3 },
      { 0, 0, 0, 0 } 
   };

#ifdef __EMX__
   _wildcard(&argc, &argv);
#endif
   
   pszProgramName = argv[0];

   while ((c = getopt_long(argc, argv, "k:c:", options, 0)) != EOF) {
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

         case 'c': /* --cipher */
            pszCipher = optarg;
            break;

         case 3: /* --no-cbc */
            fUseCBC = false;
            break;

         default:
            printUsage(1);
      }
   }

   if (optind == argc) {
      fprintf(stderr, "%s: missing parameters\n", pszProgramName);
      printUsage(1);
   }

   if (!pszCipher) pszCipher = (*cipherTable)->pszID;
   
   pCipher = findCipher(cipherTable, pszCipher,
      &cbBlock, &cbKey);
   if (!pCipher) {
      fprintf(stderr, "%s: invalid cipher specification `%s'\n",
         pszProgramName, pszCipher);
      return 0;
   }
   
   if (!pszKey) {
      pszKey = szKey;
      if (readKey("key: ", sizeof(szKey), szKey)) {
         fprintf(stderr, "%s: error reading key\n", pszProgramName);
         return 0;
      }
   }

   cr = coreHashKey(pszKey, abKey, cbKey);
   if (cr) {
      fprintf(stderr, "%s: error hashing key: %s\n",
         pszProgramName, core2str(cr));
      return 0;
   }

   cr2 = cryptCreateKey(pCipher, cbBlock, cbKey, abKey, &pKey);
   memset(abKey, 0, sizeof(abKey)); /* burn */
   if (cr2) {
      fprintf(stderr, "%s: cannot construct cipher `%s' "
         "(use `--help' to see a list of known ciphers)\n",
         pszProgramName, pszCipher);
      return 0;
   }

#ifdef __EMX__
   _fsetmode(stdin, "b");
   _fsetmode(stdout, "b");
#endif   

   for ( ; optind < argc; optind++) {

      name = argv[optind];
      if (strcmp(name, "-") == 0) {
         isstdin = true;
         name = "stdin";
         file = stdin;
      } else {
         isstdin = false;
         file = fopen(name, "rb");
         if (!file) {
            fprintf(stderr, "%s: %s: %s\n",
               pszProgramName, name, strerror(errno));
            continue;
         }
      }

      for (i = 0; ; i++) {
         
         r = fread(abData, 1, sizeof(abData), file);
         if (r != sizeof(abData)) {
            if (feof(file)) {
               if (r)
                  fprintf(stderr, "%s: %s: data missing\n",
                     pszProgramName, name);
            } else
               fprintf(stderr, "%s: %s: %s\n",
                  pszProgramName, name, strerror(errno));
            break;
         }

         cr = coreDecryptSectorData(abData, &data, pKey,
            fUseCBC ? CCRYPT_USE_CBC : 0);
         if (cr) {
            assert (cr == CORERC_BAD_CHECKSUM);
            fprintf(stderr, "%s: %s: bad checksum in sector %d\n",
               pszProgramName, name, i);
         }

         w = fwrite(data.payload, 1, sizeof(data.payload), stdout);
         if (w != sizeof(data.payload)) {
            fprintf(stderr, "%s: %s: %s\n",
               pszProgramName, name, strerror(errno));
         }
         
      }

      if (!isstdin) fclose(file);
   }

   cryptDestroyKey(pKey);

   return 0;
}
