#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>

#include <fuse.h>

#include "getopt.h"

#include "sysdep.h"
#include "ciphertable.h"
#include "corefs.h"
#include "coreutils.h"
#include "superblock.h"


static SuperBlock * pSuperBlock;
static CryptedVolume * pVolume;


static int core2sys(CoreResult cr)
{
    switch (cr) {
        case CORERC_OK: return 0;
        case CORERC_FILE_NOT_FOUND: return -ENOENT;
        case CORERC_NOT_ENOUGH_MEMORY: return -ENOMEM;
        case CORERC_FILE_EXISTS: return -EEXIST;
        case CORERC_INVALID_PARAMETER: abort();
        case CORERC_INVALID_NAME: return -EINVAL;
        case CORERC_BAD_CHECKSUM: return -EIO;
        case CORERC_BAD_INFOSECTOR: return -EIO;
        case CORERC_NOT_DIRECTORY: return -ENOTDIR;
        case CORERC_BAD_DIRECTORY: return -EIO;
        case CORERC_BAD_TYPE: return -EIO;
        case CORERC_BAD_EAS: return -EIO;
        case CORERC_CACHE_OVERFLOW: abort();
        case CORERC_READ_ONLY: return -EROFS;
        case CORERC_ISF_CORRUPT: return -EIO;
        case CORERC_ID_EXISTS: return -EIO;
        default:
            if (IS_CORERC_SYS(cr)) return -EIO;
            fprintf(stderr, "unexpected corefs error %d\n", cr);
            return -EPERM;
    }
}


static int aefs_getattr(const char * path, struct stat * stbuf)
{
    CoreResult cr;
    CryptedFileID idFile;
    CryptedFileInfo info;

    fprintf(stderr, "getattr %s\n", path);

    cr = coreQueryIDFromPath(pVolume, pSuperBlock->idRoot, path, &idFile, 0);
    if (cr) return core2sys(cr);

    cr = coreQueryFileInfo(pVolume, idFile, &info);
    if (cr) return core2sys(cr);

    stbuf->st_mode = info.flFlags;
    stbuf->st_nlink = info.cRefs;
    stbuf->st_uid = getuid();
    stbuf->st_gid = getgid();
    stbuf->st_size = info.cbFileSize;
    stbuf->st_blksize = SECTOR_SIZE;
    stbuf->st_rdev = 0;
    stbuf->st_blocks = info.csSet;
    stbuf->st_dev = 0;
    stbuf->st_ino = idFile;
    stbuf->st_atime = info.timeAccess;
    stbuf->st_mtime = info.timeWrite;
    stbuf->st_ctime = info.timeAccess; /* !!! */

    return 0;
}


static int aefs_readlink(const char * path, char * buf, size_t size)
{
    return -ENOTSUP;
}


static int aefs_getdir(const char * path, fuse_dirh_t h, fuse_dirfil_t filler)
{
    CoreResult cr;
    CryptedFileID idDir;
    CryptedDirEntry * pFirst, * pCur;

    fprintf(stderr, "getdir %s\n", path);

    cr = coreQueryIDFromPath(pVolume, pSuperBlock->idRoot, path, &idDir, 0);
    if (cr) return core2sys(cr);

    cr = coreQueryDirEntries(pVolume, idDir, &pFirst);
    if (cr) return core2sys(cr);

    filler(h, ".", 0);
    filler(h, "..", 0);

    for (pCur = pFirst; pCur; pCur = pCur->pNext) {
        filler(h, (char *) pCur->pabName, 0);
    }

    return 0;
}


static int aefs_mknod(const char * path, mode_t mode, dev_t rdev)
{
    return -ENOTSUP;
}


static int aefs_mkdir(const char * path, mode_t mode)
{
    return -ENOTSUP;
}


static int aefs_unlink(const char * path)
{
    return -ENOTSUP;
}


static int aefs_rmdir(const char * path)
{
    return -ENOTSUP;
}


static int aefs_symlink(const char * from, const char * to)
{
    return -ENOTSUP;
}


static int aefs_rename(const char * from, const char * to)
{
    return -ENOTSUP;
}


static int aefs_link(const char * from, const char * to)
{
    return -ENOTSUP;
}


static int aefs_chmod(const char * path, mode_t mode)
{
    return -ENOTSUP;
}


static int aefs_chown(const char * path, uid_t uid, gid_t gid)
{
    return -ENOTSUP;
}


static int aefs_truncate(const char * path, off_t size)
{
    return -ENOTSUP;
}


static int aefs_utime(const char * path, struct utimbuf * buf)
{
    return -ENOTSUP;
}


static int aefs_open(const char * path, int flags)
{
    CoreResult cr;
    CryptedFileID idFile;

    fprintf(stderr, "open %s\n", path);

    cr = coreQueryIDFromPath(pVolume, pSuperBlock->idRoot, path, &idFile, 0);
    if (cr) return core2sys(cr);

    return 0;
}


static int aefs_read(const char * path, char * buf, size_t size, off_t offset)
{
    CoreResult cr;
    CryptedFileID idFile;
    CryptedFilePos cbRead;

    fprintf(stderr, "read %s %ld %d\n", path, offset, size);

    cr = coreQueryIDFromPath(pVolume, pSuperBlock->idRoot, path, &idFile, 0);
    if (cr) return core2sys(cr);

    cr = coreReadFromFile(pVolume, idFile, offset, size, buf, &cbRead);
    if (cr) return core2sys(cr);

    return cbRead;
}


static int aefs_write(const char * path, const char * buf, size_t size,
    off_t offset)
{
    return -ENOTSUP;
}


static void exit_handler()
{
    exit(0);
}


static void set_signal_handlers()
{
    struct sigaction sa;

    sa.sa_handler = exit_handler;
    sigemptyset(&(sa.sa_mask));
    sa.sa_flags = 0;

    if (sigaction(SIGHUP, &sa, NULL) == -1 || 
	sigaction(SIGINT, &sa, NULL) == -1 || 
	sigaction(SIGTERM, &sa, NULL) == -1) {
	
	perror("Cannot set exit signal handlers");
        exit(1);
    }

    sa.sa_handler = SIG_IGN;
    
    if(sigaction(SIGPIPE, &sa, NULL) == -1) {
	perror("Cannot set ignored signals");
        exit(1);
    }
}


static struct fuse_operations operations = {
    getattr:	aefs_getattr,
    readlink:	aefs_readlink,
    getdir:     aefs_getdir,
    mknod:	aefs_mknod,
    mkdir:	aefs_mkdir,
    symlink:	aefs_symlink,
    unlink:	aefs_unlink,
    rmdir:	aefs_rmdir,
    rename:     aefs_rename,
    link:	aefs_link,
    chmod:	aefs_chmod,
    chown:	aefs_chown,
    truncate:	aefs_truncate,
    utime:	aefs_utime,
    open:	aefs_open,
    read:	aefs_read,
    write:	aefs_write,
};


static char *unmount_cmd;

static void cleanup()
{
    close(0);
    system(unmount_cmd);    
}

int main(int argc, char * * argv)
{
    unsigned int flags;
    struct fuse * fuse;
    CryptedVolumeParms parms;
    CoreResult cr;

    unmount_cmd = argv[1];
    fprintf(stderr, "unmount_cmd: %s\n", unmount_cmd);

    set_signal_handlers();
    atexit(cleanup);

    coreSetDefVolumeParms(&parms);

    /* Read the superblock, initialize volume structures. */
retry:
    cr = coreReadSuperBlock("", "",
        cipherTable, &parms, &pSuperBlock);
    if (cr) {
        if (pSuperBlock) coreDropSuperBlock(pSuperBlock);
        if (!parms.fReadOnly) {
            parms.fReadOnly = true;
            goto retry;
        }
        fprintf(stderr, "unable to load superblock, cr = %d\n", cr);
        assert(0);
    }
    
    pVolume = pSuperBlock->pVolume;

    flags = FUSE_DEBUG;
    fuse = fuse_new(0, flags);
    fuse_set_operations(fuse, &operations);
    fuse_loop(fuse);

    return 0;
}
