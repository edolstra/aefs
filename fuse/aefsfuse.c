/* aefsfuse.c -- FUSE front-end to AEFS.
   Copyright (C) 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: aefsfuse.c,v 1.11 2001/12/26 21:49:58 eelco Exp $

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
#include "logging.h"
#include "ciphertable.h"
#include "corefs.h"
#include "coreutils.h"
#include "superblock.h"
#include "utilutils.h"

#include "aefsfuse.h"
#include "aefsfuseint.h"


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
            logMsg(LOG_ERR, "unexpected corefs error %d", cr);
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

    logMsg(LOG_DEBUG, "lookup %ld %s", idDir, name);

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

    logMsg(LOG_DEBUG, "setattr %ld", idFile);

    cr = coreQueryFileInfo(pVolume, idFile, &info);
    if (cr) return core2sys(cr);

    if (arg->valid & FATTR_MODE) {
	logMsg(LOG_DEBUG, "set mode %od", arg->attr.mode);
	info.flFlags = 
	    (info.flFlags & ~07777) | (arg->attr.mode & 07777);
    }

    if (arg->valid & FATTR_UID) {
	logMsg(LOG_DEBUG, "set uid %d", arg->attr.uid);
	info.uid = arg->attr.uid;
    }

    if (arg->valid & FATTR_GID) {
	logMsg(LOG_DEBUG, "set gid %d", arg->attr.gid);
	info.gid = arg->attr.gid;
    }

    if (arg->valid & FATTR_UTIME) {
	logMsg(LOG_DEBUG, "set utime %ld", arg->attr.mtime);
	info.timeWrite = arg->attr.mtime;
    }

    cr = coreSetFileInfo(pVolume, idFile, &info);
    if (cr) return core2sys(cr);

    if (arg->valid & FATTR_SIZE) {
	logMsg(LOG_DEBUG, "set size %Ld", arg->attr.size);
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

    logMsg(LOG_DEBUG, "getattr %ld", idFile);

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

    logMsg(LOG_DEBUG, "getdir %ld", idDir);

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

    logMsg(LOG_DEBUG, "create %ld %s %ho %hx",
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

    logMsg(LOG_DEBUG, "remove %ld %s", idDir, pszName);

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

    logMsg(LOG_DEBUG, "rename %ld %s %ld %s", idFrom, pszFrom, idTo, pszTo);

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

    logMsg(LOG_DEBUG, "open %ld", idFile);

    cr = coreQueryFileInfo(pVolume, idFile, &info);
    if (cr) return core2sys(cr);

    return 0;
}


int do_read(struct fuse_in_header * in, struct fuse_read_in * arg, char * outbuf)
{
    CoreResult cr;
    CryptedFileID idFile = in->ino;
    CryptedFilePos cbRead;

    logMsg(LOG_DEBUG, "read %ld %Ld %d", idFile, arg->offset, arg->size);

    cr = coreReadFromFile(pVolume, idFile, arg->offset, arg->size, outbuf, &cbRead);
    if (cr) return core2sys(cr);

    return cbRead;
}


int do_write(struct fuse_in_header * in, struct fuse_write_in * arg)
{
    CoreResult cr;
    CryptedFileID idFile = in->ino;
    CryptedFilePos cbWritten;

    logMsg(LOG_DEBUG, "write %ld %Ld %d", idFile, arg->offset, arg->size);

    cr = coreWriteToFile(pVolume, idFile, arg->offset, arg->size, arg->buf, &cbWritten);
    if (cr) return core2sys(cr);

    if (arg->size != cbWritten) return -EIO;

    cr = stampFile(idFile);
    if (cr) return core2sys(cr);

    return 0;
}


/* Called by corefs whenever it marks a sector as dirty. */
static void dirtyCallBack(CryptedVolume * pVolume, bool fDirty)
{
    CoreResult cr;
    
    logMsg(LOG_DEBUG, "dirtyCallBack, fDirty=%d", fDirty);

    if (fDirty) { /* the volume now has dirty sectors */

        if (!(pSuperBlock->flFlags & SBF_DIRTY)) {
            pSuperBlock->flFlags |= SBF_DIRTY;
            cr = coreWriteSuperBlock(pSuperBlock,
                CWS_NOWRITE_SUPERBLOCK1);
            if (cr)
                logMsg(LOG_ERR, "error setting dirty flag, cr=%d", cr);
        }

    } else { /* the volume now has no dirty sectors */
        /* Do nothing.  The superblock's dirty flag is periodically
           cleared by the lazy writer or by volumeDirty(). */
    }

}


/* Flush all dirty data on a volume, clear the dirty bit. */
void commitVolume()
{
    CoreResult cr;

    logMsg(LOG_DEBUG, "flushing volume");

    /* Flush dirty data. */
    cr = coreFlushVolume(pVolume);
    if (cr) {
        logMsg(LOG_ERR, "error flushing volume, cr=%d", cr);
	return;
    }

    /* Clear the dirty bit in the superblock. */
    if (pSuperBlock->flFlags & SBF_DIRTY) {
        pSuperBlock->flFlags &= ~SBF_DIRTY;
        cr = coreWriteSuperBlock(pSuperBlock,
            CWS_NOWRITE_SUPERBLOCK1);
        if (cr) {
            logMsg(LOG_ERR, "error clearing dirty flag, cr=%d", cr);
            pSuperBlock->flFlags |= SBF_DIRTY; /* retry */
	    return;
        }
    }
}


static int readBuf(int fd, void * buf, int size)
{
    int r;
    while (size) {
        r = read(fd, buf, size);
        if (r == -1 && errno != EINTR) return -1;
        if (r == 0) return -1;
        buf += r;
        size -= r;
    }
    return 0;
}


static FuseMountParams params;
static int fdFrom, fdTo;


static void writeResult(CoreResult cr)
{
    if (write(fdTo, &cr, sizeof(cr)) != sizeof(cr)) {
        logMsg(LOG_ERR, "cannot write result: %s",
            strerror(errno));
    }
}


/* Return true iff somebody unmounted us. */
static bool run(void)
{
    bool fUnmounted;
    CryptedVolumeParms parms;
    CoreResult cr;

    /* Move the fuse file descriptor away from 0.  Must be done prior
       to daemonizing. */
    if (!dupFuseFD()) {
        writeResult(CORERC_SYS + SYS_UNKNOWN);
        return false;
    }

    /* Daemonize. */
    if (!fDebug) daemon(0, 0);
    
    coreSetDefVolumeParms(&parms);
    parms.fReadOnly = params.fReadOnly;
    parms.dirtyCallBack = dirtyCallBack;

    /* Read the superblock, initialize volume structures.  Note: we
       cannot call daemon() after coreReadSuperBlock(), since daemon()
       works by forking and children do not inherit file locks. */
retry:
    cr = coreReadSuperBlock(params.szBasePath, params.szPassPhrase,
        cipherTable, &parms, &pSuperBlock);
    if (cr) {
        if (pSuperBlock) coreDropSuperBlock(pSuperBlock);
        if (!parms.fReadOnly) {
            parms.fReadOnly = true;
            goto retry;
        }
	logMsg(LOG_ERR, "%s: unable to read superblock: %s", 
	    pszProgramName, core2str(cr));
        writeResult(cr);
        return false;
    }

    writeResult(CORERC_OK);
    
    pVolume = pSuperBlock->pVolume;

    fUnmounted = runLoop();

    commitVolume();
    coreDropSuperBlock(pSuperBlock);

    return fUnmounted;
}


int main(int argc, char * * argv)
{
    char * pszEnv, * pszUnmount;

    pszProgramName = argv[0];
    sysInitPRNG();

    /* Get the file descriptors used to communicate with mntaefsfuse. */
    pszEnv = getenv("AEFS_FD");
    if (!pszEnv) {
        fprintf(stderr, "%s: must be run by mntaefsfuse\n", 
            pszProgramName);
        return 1;
    }
    if (sscanf(pszEnv, "%d %d", &fdFrom, &fdTo) != 2) abort();

    /* Read the parameters. */
    if (readBuf(fdFrom, &params, sizeof(params))) abort();
    close(fdFrom);
    logMsg(LOG_DEBUG, "mounting AEFS volume at %s", params.szBasePath);

    fDebug = params.fDebug;

    /* Get the unmounting command. */
    pszUnmount = getenv("_FUSE_UNMOUNT_CMD");

    /* Do actual work, then unmount unless somebody else did. */
    if (!run()) {
        logMsg(LOG_DEBUG, "unmounting using: %s", pszUnmount);
        system(pszUnmount);
    }

    memset(&params, 0, sizeof(params)); /* burn */

    return 0;
}
