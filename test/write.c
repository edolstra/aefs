#include <assert.h>
#include <string.h>

#include "ciphertable.h"
#include "corefs.h"
#include "coreutils.h"
#include "superblock.h"


int main(int argc, char * * argv)
{
    CryptedVolumeParms parms;
    CoreResult cr;

    SuperBlock * pSuperBlock;
    CryptedVolume * pVolume;

    CryptedFileInfo info;
    CryptedFileID idFile;
    CryptedFilePos cbWritten, cbRead;

    octet buf[100000];
    int i;

    sysInitPRNG();

    coreSetDefVolumeParms(&parms);
    parms.csMaxCached = 10;
    parms.csIOGranularity = 5;
   
    cr = coreReadSuperBlock(TESTVOL "/", TESTPW,
        cipherTable, &parms, &pSuperBlock);
    assert(cr == CORERC_OK);

    pVolume = pSuperBlock->pVolume;

    memset(&info, 0, sizeof(info));
    info.flFlags = CFF_IFREG;
    info.cRefs = 1;
    info.cbFileSize = 0;
    info.idParent = 0;
    cr = coreCreateBaseFile(pVolume, &info, &idFile);
    assert(cr == CORERC_OK);

    memset(buf, 0xaa, sizeof(buf));
    cr = coreWriteToFile(pVolume, idFile, 0, sizeof(buf), buf, &cbWritten);
    assert(cr == CORERC_OK && cbWritten == sizeof(buf));

    /* Regression test: a bug in basefile.c caused writes that were
       entirely in the initialised area to zero out the remainder of
       the last written sector unless it was in the cache. */
    cr = coreWriteToFile(pVolume, idFile, 0, 1000, buf, &cbWritten);
    assert(cr == CORERC_OK && cbWritten == 1000);

    memset(buf, 0xff, sizeof(buf));
    cr = coreReadFromFile(pVolume, idFile, 0, sizeof(buf), buf, &cbRead);
    assert(cr == CORERC_OK && cbRead == sizeof(buf));
    for (i = 0; i < sizeof(buf); i++)
        assert(buf[i] == 0xaa);
    
    cr = coreDropSuperBlock(pSuperBlock);
    assert(cr == CORERC_OK);

    return 0;
}
