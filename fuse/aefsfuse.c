#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include "getopt.h"

#include "sysdep.h"
#include "ciphertable.h"
#include "corefs.h"
#include "coreutils.h"
#include "superblock.h"
#include "utilutils.h"

#include "aefsfuse.h"


char * pszProgramName;


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


static void storeAttr(CryptedFileInfo * info, struct fuse_attr * attr)
{
    attr->mode = info->flFlags;
    attr->nlink = info->cRefs;
    attr->uid = getuid();
    attr->gid = getgid();
    attr->rdev = 0;
    attr->size = info->cbFileSize;
/*     attr->blksize = SECTOR_SIZE; !!! */
    attr->blocks = info->csSet;
    attr->atime = info->timeAccess;
    attr->mtime = info->timeWrite;
    attr->ctime = info->timeAccess; /* !!! */
    attr->_dummy = 4096; /* ??? */
}


int do_lookup(struct fuse_in_header * in, char * name, struct fuse_lookup_out * out)
{
    CoreResult cr;
    CryptedFileID idDir = in->ino, idFile;
    CryptedFileInfo info;

/*     fprintf(stderr, "lookup %ld %s\n", idDir, name); */

    cr = coreQueryIDFromPath(pVolume, idDir, name, &idFile, 0);
    if (cr) return core2sys(cr);

    cr = coreQueryFileInfo(pVolume, idFile, &info);
    if (cr) return core2sys(cr);

    out->ino = idFile;
    storeAttr(&info, &out->attr);

    return 0;
}


int do_getattr(struct fuse_in_header * in, struct fuse_getattr_out * out)
{
    CoreResult cr;
    CryptedFileID idFile = in->ino;
    CryptedFileInfo info;

/*     fprintf(stderr, "getattr %ld\n", idFile); */

    cr = coreQueryFileInfo(pVolume, idFile, &info);
    if (cr) return core2sys(cr);

    storeAttr(&info, &out->attr);

    return 0;
}


#if 0
int aefs_readlink(const char * path, char * buf, size_t size)
{
    return -ENOTSUP;
}
#endif


static int filler(int fd, CryptedFileID id, char * name)
{
    struct fuse_dirent dirent;
    size_t reclen;
    size_t res;

    dirent.ino = id;
    dirent.namelen = strlen(name);
    strncpy(dirent.name, name, sizeof(dirent.name));
    dirent.type = 0;
    reclen = FUSE_DIRENT_SIZE(&dirent);
    res = write(fd, &dirent, reclen);
    if(res != reclen) {
        perror("writing directory file");
        return -EIO;
    }
    return 0;
}

int do_getdir(struct fuse_in_header * in, struct fuse_getdir_out * out)
{
    CoreResult cr;
    CryptedFileID idDir = in->ino;
    CryptedFileInfo info;
    CryptedDirEntry * pFirst, * pCur;

/*     fprintf(stderr, "getdir %ld\n", idDir); */

    out->fd = creat("/tmp/fuse_tmp", 0600);
    if (out->fd == -1) return -errno;
    unlink("/tmp/fuse_tmp");

    cr = coreQueryFileInfo(pVolume, idDir, &info);
    if (cr) return core2sys(cr);

    filler(out->fd, idDir, ".");
    filler(out->fd, info.idParent, "..");

    cr = coreQueryDirEntries(pVolume, idDir, &pFirst);
    if (cr) return core2sys(cr);

    for (pCur = pFirst; pCur; pCur = pCur->pNext) {
        filler(out->fd, pCur->idFile, (char *) pCur->pabName);
    }

    coreFreeDirEntries(pFirst); /* !!! */

    return 0;
}


#if 0
int aefs_mknod(const char * path, mode_t mode, dev_t rdev)
{
    return -ENOTSUP;
}


int aefs_mkdir(const char * path, mode_t mode)
{
    return -ENOTSUP;
}


int aefs_unlink(const char * path)
{
    return -ENOTSUP;
}


int aefs_rmdir(const char * path)
{
    return -ENOTSUP;
}


int aefs_symlink(const char * from, const char * to)
{
    return -ENOTSUP;
}


int aefs_rename(const char * from, const char * to)
{
    return -ENOTSUP;
}


int aefs_link(const char * from, const char * to)
{
    return -ENOTSUP;
}


int aefs_chmod(const char * path, mode_t mode)
{
    return -ENOTSUP;
}


int aefs_chown(const char * path, uid_t uid, gid_t gid)
{
    return -ENOTSUP;
}


int aefs_truncate(const char * path, off_t size)
{
    return -ENOTSUP;
}


int aefs_utime(const char * path, struct utimbuf * buf)
{
    return -ENOTSUP;
}
#endif


int do_open(struct fuse_in_header * in, struct fuse_open_in * arg)
{
    CoreResult cr;
    CryptedFileID idFile = in->ino;
    CryptedFileInfo info;

/*     fprintf(stderr, "open %ld\n", idFile); */

    cr = coreQueryFileInfo(pVolume, idFile, &info);
    if (cr) return core2sys(cr);

    return 0;
}


int do_read(struct fuse_in_header * in, struct fuse_read_in * arg, char * outbuf)
{
    CoreResult cr;
    CryptedFileID idFile = in->ino;
    CryptedFilePos cbRead;

/*     fprintf(stderr, "read %ld %Ld %d\n", idFile, arg->offset, arg->size); */

    cr = coreReadFromFile(pVolume, idFile, arg->offset, arg->size, outbuf, &cbRead);
    if (cr) return core2sys(cr);

    return cbRead;
}


#if 0
int aefs_write(const char * path, const char * buf, size_t size,
    off_t offset)
{
    return -ENOTSUP;
}
#endif


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


static char *unmount_cmd;

static void cleanup()
{
    close(0);
    system(unmount_cmd);    
}

int main(int argc, char * * argv)
{
    CryptedVolumeParms parms;
    CoreResult cr;
    char szKey[1024], * pszKey = 0, * pszBasePath;

    unmount_cmd = argv[1];
    pszBasePath = argv[2];
    
    fprintf(stderr, "unmount_cmd: `%s', \n", unmount_cmd);

    set_signal_handlers();
    atexit(cleanup);

    coreSetDefVolumeParms(&parms);

    /* Ask the use to enter the key, if it wasn't specified with "-k". */
    if (!pszKey) {
        pszKey = szKey;
        if (readKey("key: ", sizeof(szKey), szKey)) {
            fprintf(stderr, "%s: error reading key\n", pszProgramName);
            return 1;
        }
    }

    /* Read the superblock, initialize volume structures. */
retry:
    cr = coreReadSuperBlock(pszBasePath, pszKey,
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

    runLoop();

    return 0;
}
