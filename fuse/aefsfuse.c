#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
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

bool fDebug = false;


void dprintf(const char * fmt, ...)
{
    va_list args;
    if (fDebug) {
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
    }
}


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


/* Stamp a file's mtime. */
static CoreResult stampFile(CryptedFileID idFile)
{
    CoreResult cr;
    CryptedFileInfo info;

    /* Update the directory's last-written (mtime) timestamp. */
    cr = coreQueryFileInfo(pVolume, idFile, &info);
    if (cr) return cr;
    
    info.timeWrite = time(0);
    
    cr = coreSetFileInfo(pVolume, idFile, &info);
    if (cr) return cr;

    return CORERC_OK;
}


int do_lookup(struct fuse_in_header * in, char * name, struct fuse_lookup_out * out)
{
    CoreResult cr;
    CryptedFileID idDir = in->ino, idFile;
    CryptedFileInfo info;

    dprintf("lookup %ld %s\n", idDir, name);

    cr = coreQueryIDFromPath(pVolume, idDir, name, &idFile, 0);
    if (cr) return core2sys(cr);

    cr = coreQueryFileInfo(pVolume, idFile, &info);
    if (cr) return core2sys(cr);

    out->ino = idFile;
    storeAttr(&info, &out->attr);

    return 0;
}


int do_setattr(struct fuse_in_header * in, struct fuse_setattr_in * arg, 
    struct fuse_setattr_out * out)
{
    CoreResult cr;
    CryptedFileID idFile = in->ino;
    CryptedFileInfo info;

    dprintf("setattr %ld\n", idFile);

    cr = coreQueryFileInfo(pVolume, idFile, &info);
    if (cr) return core2sys(cr);

    if (arg->valid & FATTR_MODE) {
	dprintf("set mode %od\n", arg->attr.mode);
	info.flFlags = 
	    (info.flFlags & ~07777) | (arg->attr.mode & 07777);
    }

    if (arg->valid & FATTR_UID) {
	dprintf("set uid %d\n", arg->attr.uid);
	info.uid = arg->attr.uid;
    }

    if (arg->valid & FATTR_GID) {
	dprintf("set gid %d\n", arg->attr.gid);
	info.gid = arg->attr.gid;
    }

    if (arg->valid & FATTR_UTIME) {
	dprintf("set utime %ld\n", arg->attr.mtime);
	info.timeWrite = arg->attr.mtime;
    }

    cr = coreSetFileInfo(pVolume, idFile, &info);
    if (cr) return core2sys(cr);

    if (arg->valid & FATTR_SIZE) {
	dprintf("set size %Ld\n", arg->attr.size);
	cr = coreSetFileSize(pVolume, idFile, arg->attr.size);
	if (cr) return core2sys(cr);
	cr = coreQueryFileInfo(pVolume, idFile, &info);
	if (cr) return core2sys(cr);
    }

    storeAttr(&info, &out->attr);

    return 0;
}


int do_getattr(struct fuse_in_header * in, struct fuse_getattr_out * out)
{
    CoreResult cr;
    CryptedFileID idFile = in->ino;
    CryptedFileInfo info;

    dprintf("getattr %ld\n", idFile);

    cr = coreQueryFileInfo(pVolume, idFile, &info);
    if (cr) return core2sys(cr);

    storeAttr(&info, &out->attr);

    return 0;
}


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

    dprintf("getdir %ld\n", idDir);

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


int createFile(CryptedFileID idDir, char * pszName,
    unsigned int mode, unsigned int rdev,
    unsigned long * ino, struct fuse_attr * attr)
{
    CoreResult cr;
    CryptedFileID idFile;
    CryptedFileInfo info;

    dprintf("create %ld %s %ho %hx\n",
	idDir, pszName, mode, rdev);

    mode = mode & (CFF_IFMT | 07777);
    switch (mode & CFF_IFMT) {
        case CFF_IFREG: /* regular file */
        case CFF_IFLNK: /* symlink */
        case CFF_IFDIR: /* directory */
            break;
        default: /* device nodes are not supported */
            return -EACCES;
    }

    /* Create the file. */
    memset(&info, 0, sizeof(info));
    info.flFlags = mode;
    info.cRefs = 1;
    info.cbFileSize = 0;
    info.timeCreation = info.timeAccess = info.timeWrite = time(0);
    info.idParent = CFF_ISDIR(info.flFlags) ? idDir : 0;
    info.uid = getuid();
    info.gid = getgid();
    cr = coreCreateBaseFile(pVolume, &info, &idFile);
    if (cr) return core2sys(cr);

    /* Add an entry for the newly created file to the directory. */
    cr = coreAddEntryToDir(pVolume, idDir, pszName, idFile, 0);
    if (cr) {
	coreDeleteFile(pVolume, idFile);
	return core2sys(cr);
    }

    cr = stampFile(idDir);
    if (cr) return core2sys(cr);

    if (ino) *ino = idFile;
    if (attr) storeAttr(&info, attr);

    return 0;
}


int do_mknod(struct fuse_in_header * in, struct fuse_mknod_in * arg, 
    struct fuse_mknod_out * out)
{
    return createFile(in->ino, arg->name, arg->mode, arg->rdev,
	&out->ino, &out->attr);
}


#if 0
int do_mkdir(struct fuse_in_header * in, struct fuse_mkdir_in * arg)
{
    return createFile(in->ino, arg->name, arg->mode | CFF_IFDIR, 0, 0, 0);
}
#endif


int do_remove(struct fuse_in_header * in, char * pszName)
{
    CoreResult cr;
    CryptedFileID idDir = in->ino, idFile;
    CryptedFileInfo info;
    CryptedDirEntry * pFirstEntry;

    dprintf("remove %ld %s\n", idDir, pszName);

    cr = coreQueryIDFromPath(pVolume, idDir, pszName, &idFile, 0);
    if (cr) return core2sys(cr);

    cr = coreQueryFileInfo(pVolume, idFile, &info);
    if (cr) return core2sys(cr);

    if (CFF_ISDIR(info.flFlags)) {
	cr = coreQueryDirEntries(pVolume, idFile, &pFirstEntry);
	coreFreeDirEntries(pFirstEntry);
	if (cr) return core2sys(cr);
	if (pFirstEntry) return -ENOTEMPTY;
    }

    /* Remove the directory entry. */
    cr = coreMoveDirEntry(pVolume, pszName, idDir, 0, 0);
    if (cr) return core2sys(cr);

    /* Stamp the directory's mtime. */
    cr = stampFile(idDir);
    if (cr) return core2sys(cr);

    /* Decrease reference count and delete if appropriate. */
    info.cRefs--;
    if (CFF_ISDIR(info.flFlags) || (info.cRefs == 0))
        cr = coreDeleteFile(pVolume, idFile);
    else
        cr = coreSetFileInfo(pVolume, idFile, &info);

    return core2sys(cr);
}


int do_rename(struct fuse_in_header * in, struct fuse_rename_in * arg)
{
    CoreResult cr;
    CryptedFileID idFrom = in->ino, idTo = arg->newdir;
    char * pszFrom = arg->names;
    char * pszTo = arg->names + strlen(pszFrom) + 1;

    dprintf("rename %ld %s %ld %s\n", idFrom, pszFrom, idTo, pszTo);

    cr = coreMoveDirEntry(pVolume,
        pszFrom, idFrom,
        pszTo, idTo);
    if (cr) return core2sys(cr);
    
    /* Stamp the mtimes of the directories. */
    if (cr = stampFile(idFrom)) return core2sys(cr);
    if ((idFrom != idTo) && (cr = stampFile(idTo))) return core2sys(cr);

    return 0;
}


int do_open(struct fuse_in_header * in, struct fuse_open_in * arg)
{
    CoreResult cr;
    CryptedFileID idFile = in->ino;
    CryptedFileInfo info;

    dprintf("open %ld\n", idFile);

    cr = coreQueryFileInfo(pVolume, idFile, &info);
    if (cr) return core2sys(cr);

    return 0;
}


int do_read(struct fuse_in_header * in, struct fuse_read_in * arg, char * outbuf)
{
    CoreResult cr;
    CryptedFileID idFile = in->ino;
    CryptedFilePos cbRead;

    dprintf("read %ld %Ld %d\n", idFile, arg->offset, arg->size);

    cr = coreReadFromFile(pVolume, idFile, arg->offset, arg->size, outbuf, &cbRead);
    if (cr) return core2sys(cr);

    return cbRead;
}


int do_write(struct fuse_in_header * in, struct fuse_write_in * arg)
{
    CoreResult cr;
    CryptedFileID idFile = in->ino;
    CryptedFilePos cbWritten;

    dprintf("write %ld %Ld %d\n", idFile, arg->offset, arg->size);

    cr = coreWriteToFile(pVolume, idFile, arg->offset, arg->size, arg->buf, &cbWritten);
    if (cr) return core2sys(cr);

    if (arg->size != cbWritten) return -EIO;

    cr = stampFile(idFile);
    if (cr) return core2sys(cr);

    return 0;
}


#define FUSE_UMOUNT_CMD_ENV  "_FUSE_UNMOUNT_CMD"

static char *unmount_cmd;

static void cleanup()
{
    close(0);
/*     system(unmount_cmd); */
}


int main(int argc, char * * argv)
{
    CryptedVolumeParms parms;
    CoreResult cr;
    char szKey[1024], * pszKey = 0, * pszBasePath;

    pszBasePath = argv[1];

    unmount_cmd = getenv(FUSE_UMOUNT_CMD_ENV);
    dprintf("unmount_cmd: `%s', \n", unmount_cmd);

    sysInitPRNG();

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

    cleanup();

    coreDropSuperBlock(pSuperBlock);

    return 0;
}
