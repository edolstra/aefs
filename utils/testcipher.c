/* testcipher.c -- Test cipher encryption/decryption speed.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: testcipher.c,v 1.3 2001/09/23 13:30:25 eelco Exp $

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
#include <time.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include "cipher.h"
#include "ciphertable.h"

#include "utilutils.h"


char * pszProgramName;


static void printUsage(int status)
{
   printf("\
Usage: %s t CIPHER TIMES  (= encrypt & decrypt TIMES times)\n\
  *OR*\n\
Usage: %s v CIPHER {d|e] KEY TEXT  (= en/decrypt TEXT using KEY)\n\
",
      pszProgramName, pszProgramName);
   exit(status);
}


static int fromHex(char c)
{
   c = toupper(c);
   if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;
   else if (c >= '0' && c <= '9')
      return c - '0';
   else
      printUsage(1);
}


static void readVector(char * pszVec, 
   unsigned int cbVec, octet * pabVec)
{
   unsigned int i = cbVec;
   memset(pabVec, 0, cbVec);
   for ( ; i && pszVec[0] && pszVec[1]; pszVec += 2, pabVec++, i--) {
      *pabVec = (fromHex(pszVec[0]) << 4) | fromHex(pszVec[1]);
   }
   if (!i && *pszVec) printUsage(1);
}


int main(int argc, char * * argv)
{
   CipherResult cr;
   unsigned int cIterations;
   char * pszCipher;
   Cipher * pCipher;
   unsigned int cbBlock, cbKey;
   octet abKey[MAX_KEY_SIZE];
   Key * pKey;
   octet abInit[MAX_BLOCK_SIZE];
   octet abVector[MAX_BLOCK_SIZE];
   unsigned int i;
   clock_t t1, t2, t3, t4;
   float ta, tb;
   char what, what2;

   pszProgramName = argv[0];

   if (argc < 4) printUsage(1);
   
   what = argv[1][0];
   if (what != 't' && what != 'v') printUsage(1);

   pszCipher = argv[2];
   pCipher = findCipher(cipherTable, pszCipher, &cbBlock, &cbKey);
   assert(pCipher);

   if (what == 't') {

      if (argc != 4) printUsage(1);
      
      cIterations = atoi(argv[3]);
   
      printf("%16s-%04d-%04d: ", pCipher->pszID, cbKey * 8, cbBlock * 8);
   
      /* Dummy key. */
      for (i = 0; i < cbKey; i++)
         abKey[i] = i;
      
      cr = cryptCreateKey(pCipher, cbBlock, cbKey, abKey, &pKey);
      assert(!cr);
      
      /* Initial test vector. */
      for (i = 0; i < cbBlock; i++)
         abInit[i] = i;
      memcpy(abVector, abInit, cbBlock);

      /* Encrypt cIterations times. */
      t1 = clock();
      for (i = cIterations; i; i--) {
         pKey->pCipher->encryptBlock(pKey, abVector);
      }
      t2 = clock();

      /* Decrypt cIterations times. */
      t3 = clock();
      for (i = cIterations; i; i--) {
         pKey->pCipher->decryptBlock(pKey, abVector);
      }
      t4 = clock();
      
      /* Result should match test vector. */
      for (i = 0; i < cbBlock; i++)
         assert(abInit[i] == abVector[i]);

      ta = (t2 - t1) / (float) CLOCKS_PER_SEC;
      tb = (t4 - t3) / (float) CLOCKS_PER_SEC;
      
      printf("%8.3f %8.3f %8.3f %8.3f\n",
         ta, /* time for encryption */
         tb, /* time for decryption */
         /* encryption speed in Mb/s */
         (cbBlock * cIterations) / ta / (1024 * 1024),
         /* decryption speed in Mb/s */
         (cbBlock * cIterations) / tb / (1024 * 1024)); 
      
   } else if (what == 'v') {
      
      if (argc != 6) printUsage(1);
      
      what2 = argv[3][0];
      if (what2 != 'e' && what2 != 'd') printUsage(1);

      readVector(argv[4], cbKey, abKey);
      
      readVector(argv[5], cbBlock, abVector);
      
      cr = cryptCreateKey(pCipher, cbBlock, cbKey, abKey, &pKey);
      assert(!cr);
      
      if (what2 == 'e')
         pKey->pCipher->encryptBlock(pKey, abVector);
      else
         pKey->pCipher->decryptBlock(pKey, abVector);
      
      for (i = 0; i < cbBlock; i++)
         printf("%02x", (int) abVector[i]);
      printf("\n");
   }

   return 0;
}
