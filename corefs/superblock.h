/* superblock.h -- Header file to the standard superblock code.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: superblock.h,v 1.7 2001/12/26 17:37:44 eelco Exp $

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

#ifndef _SUPERBLOCK_H
#define _SUPERBLOCK_H

#include "corefs.h"


/* Error codes. */
#define CORERC_BAD_SUPERBLOCK    200
#define CORERC_UNKNOWN_CIPHER    201
#define CORERC_MISC_CIPHER       202
#define CORERC_BAD_VERSION       203

/* Values for SuperBlock.version. */
#define SBV_1_0            0x010000
#define SBV_CURRENT        SBV_1_0

/* Flags for SuperBlock.flFlags. */
#define SBF_DIRTY          1

/* Magic value for SuperBlock2OnDisk.magic. */
#define SUPERBLOCK2_MAGIC  0x5a180a57

/* File names for the superblock files. */
#define SUPERBLOCK1_NAME "SUPERBLK.1" /* unencrypted part */
#define SUPERBLOCK2_NAME "SUPERBLK.2" /* encrypted part */
#define ENCDATAKEY_NAME  "KEY"        /* encrypted data key */

/* Values for coreWriteSuperBlock(flags). */
#define CWS_NOWRITE_SUPERBLOCK1 1

/* Maximum size of a passphrase (incl. null). */
#define MAX_PASSPHRASE_SIZE 256 /* bytes */



typedef struct {
      char szBasePath[MAX_VOLUME_BASE_PATH_NAME];
      CryptedVolume * pVolume;
      Key * pDataKey;
      /* Only needed for coreWriteKey(). */
      octet abDataKey[MAX_KEY_SIZE];

      unsigned int version;
      unsigned int flFlags;
      CryptedFileID idRoot;
      char szLabel[12]; /* DOS disk label */
      char szDescription[128];
      bool fEncryptedKey;

      uint32 magic;

      File * pSB2File;
} SuperBlock;


#pragma pack(1)
typedef struct {
      octet random[32];
      octet magic[4];
      octet version[4];
      octet flFlags[4];
      octet idRoot[4];
      octet szLabel[12];
      octet szDescription[128];
} SuperBlock2OnDisk;
#pragma pack()


CoreResult coreHashPhrase(char * pszPhrase, octet * pabKey, 
   unsigned int cbKey);

CoreResult coreReadSuperBlock(char * pszBasePath, char * pszPassPhrase,
   Cipher * * papCipher, CryptedVolumeParms * pParms,
   SuperBlock * * ppSuperBlock);

CoreResult coreWriteSuperBlock(SuperBlock * pSuperBlock, 
   unsigned int flags);

CoreResult coreWriteDataKey(SuperBlock * pSuperBlock, 
   char * pszPassPhrase);

CoreResult coreDropSuperBlock(SuperBlock * pSuperBlock);


#endif /* !_SUPERBLOCK_H */
