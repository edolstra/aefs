/* aefsfuse.c -- FUSE front-end to AEFS.
   Copyright (C) 2001 Eelco Dolstra (eelco@cs.uu.nl).

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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/vfs.h>

#include "getopt.h"

#include "ciphertable.h"
#include "corefs.h"
#include "coreutils.h"
#include "superblock.h"
#include "utilutils.h"

#include "sysdep.h"
#include "logging.h"

#include <fuse/fuse.h>
#include <fuse/fuse_kernel.h>
#include <fuse/fuse_lowlevel.h>


void commitVolume();


char * pszProgramName;


static SuperBlock * pSuperBlock;
static CryptedVolume * pVolume;

static bool fForceMount = false;
static bool fReadOnly = false;
static char szBasePath[PATH_MAX + 1];
static char szMountPoint[PATH_MAX + 1];
static int fdRes[2];


static int core2sys(CoreResult cr)
{
    switch (cr) {
        case CORERC_OK: return 0;
        case CORERC_FILE_NOT_FOUND: return ENOENT;
        case CORERC_NOT_ENOUGH_MEMORY: return ENOMEM;
        case CORERC_FILE_EXISTS: return EEXIST;
        case CORERC_INVALID_PARAMETER: abort();
        case CORERC_INVALID_NAME: return EINVAL;
        case CORERC_BAD_CHECKSUM: return EIO;
        case CORERC_BAD_INFOSECTOR: return EIO;
        case CORERC_NOT_DIRECTORY: return ENOTDIR;
        case CORERC_BAD_DIRECTORY: return EIO;
        case CORERC_BAD_TYPE: return EIO;
        case CORERC_BAD_EAS: return EIO;
        case CORERC_CACHE_OVERFLOW: abort();
        case CORERC_READ_ONLY: return EROFS;
        case CORERC_ISF_CORRUPT: return EIO;
        case CORERC_ID_EXISTS: return EIO;
        case CORERC_NOT_SYMLINK: return EINVAL;
        case CORERC_NAME_TOO_LONG: return ENAMETOOLONG;
        case CORERC_BAD_SYMLINK: return EIO;
        default:
            if (IS_CORERC_SYS(cr)) return EIO;
            logMsg(LOG_ERR, "unexpected corefs error %d", cr);
            return EPERM;
    }
}


static void storeAttr(CryptedFileID idFile, CryptedFileInfo * info,
    struct stat * st)
{
    memset(st, 0, sizeof(struct stat));
    st->st_ino = idFile;
    st->st_mode = info->flFlags;
    st->st_nlink = info->cRefs;
    st->st_uid = getuid();
    st->st_gid = getgid();
    st->st_rdev = 0;
    st->st_size = info->cbFileSize;
    st->st_blksize = SECTOR_SIZE;
    st->st_blocks = info->csSet;
    st->st_atime = info->timeAccess;
    st->st_mtime = info->timeWrite;
    st->st_ctime = info->timeAccess; /* !!! */
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


static unsigned long generation = 0;


static void fillEntryOut(struct fuse_entry_param * out,
    CryptedFileID idFile, CryptedFileInfo * info)
{
    out->ino = idFile;
    out->generation = generation++;
    out->entry_timeout = 1.0; /* sec */
    out->attr_timeout = 1.0; /* sec */
    storeAttr(idFile, info, &out->attr);
}


static void do_lookup(fuse_req_t req, fuse_ino_t parent, const char * name)
{
    CoreResult cr;
    CryptedFileID idDir = parent, idFile;
    CryptedFileInfo info;

    logMsg(LOG_DEBUG, "lookup %ld %s", idDir, name);

    cr = coreQueryIDFromPath(pVolume, idDir, name, &idFile, 0);
    if (cr) { fuse_reply_err(req, core2sys(cr)); return; }

    cr = coreQueryFileInfo(pVolume, idFile, &info);
    if (cr) { fuse_reply_err(req, core2sys(cr)); return; }

    struct fuse_entry_param entry;
    fillEntryOut(&entry, idFile, &info);

    fuse_reply_entry(req, &entry);
}


static void do_setattr(fuse_req_t req, fuse_ino_t ino, struct stat * attr,
    int to_set, struct fuse_file_info * fi)
{
    CoreResult cr;
    CryptedFileID idFile = ino;
    CryptedFileInfo info;

    logMsg(LOG_DEBUG, "setattr %ld", idFile);

    cr = coreQueryFileInfo(pVolume, idFile, &info);
    if (cr) { fuse_reply_err(req, core2sys(cr)); return; }

    if (to_set & FUSE_SET_ATTR_MODE) {
	logMsg(LOG_DEBUG, "set mode %od", attr->st_mode);
	info.flFlags = 
	    (info.flFlags & ~07777) | (attr->st_mode & 07777);
    }

    if (to_set & FUSE_SET_ATTR_UID) {
	logMsg(LOG_DEBUG, "set uid %d", attr->st_uid);
	info.uid = attr->st_uid;
    }

    if (to_set & FUSE_SET_ATTR_GID) {
	logMsg(LOG_DEBUG, "set gid %d", attr->st_gid);
	info.gid = attr->st_gid;
    }

    if (to_set & FUSE_SET_ATTR_MTIME) {
	logMsg(LOG_DEBUG, "set mtime %ld", attr->st_mtime);
	info.timeWrite = attr->st_mtime;
    }

    cr = coreSetFileInfo(pVolume, idFile, &info);
    if (cr) { fuse_reply_err(req, core2sys(cr)); return; }

    if (to_set & FUSE_SET_ATTR_SIZE) {
	logMsg(LOG_DEBUG, "set size %Ld", attr->st_size);
	cr = coreSetFileSize(pVolume, idFile, attr->st_size);
	if (cr) { fuse_reply_err(req, core2sys(cr)); return; }
	cr = coreQueryFileInfo(pVolume, idFile, &info);
	if (cr) { fuse_reply_err(req, core2sys(cr)); return; }
    }

    struct stat st;
    storeAttr(idFile, &info, &st);

    fuse_reply_attr(req, &st, 1.0);
}


static void do_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    CoreResult cr;
    CryptedFileID idFile = ino;
    CryptedFileInfo info;

    logMsg(LOG_DEBUG, "getattr %ld", idFile);

    cr = coreQueryFileInfo(pVolume, idFile, &info);
    if (cr) { fuse_reply_err(req, core2sys(cr)); return; }

    struct stat st;
    storeAttr(idFile, &info, &st);

    fuse_reply_attr(req, &st, 1.0);
}


static void do_readlink(fuse_req_t req, fuse_ino_t ino)
{
    CoreResult cr;
    CryptedFileID idLink = ino;

    logMsg(LOG_DEBUG, "readlink %ld", idLink);

    char link[PATH_MAX + 1];
    cr = coreReadSymlink(pVolume, idLink, PATH_MAX, link);
    if (cr) { fuse_reply_err(req, core2sys(cr)); return; }

    fuse_reply_readlink(req, link);
}


typedef struct {
    unsigned int len;
    unsigned char * buffer;
} DirContents;


static CoreResult filler(DirContents * contents, CryptedFileID id, char * name)
{
    /* Copied from fill_dir() in FUSE. */
    size_t namelen = strlen(name);
    size_t entsize = fuse_dirent_size(namelen);
    
    if (namelen > FUSE_NAME_MAX) return CORERC_INVALID_NAME;

    contents->buffer = realloc(contents->buffer, contents->len + entsize); /* !!! insecure */
    if (!contents->buffer) return CORERC_NOT_ENOUGH_MEMORY;

    struct stat st;
    memset(&st, 0, sizeof(struct stat));
    st.st_ino = id;
    
    fuse_add_dirent(
        contents->buffer + contents->len,
        name, &st, contents->len + entsize);

    contents->len += entsize;
    
    return CORERC_OK;
}


static void do_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info * fi)
{
    CoreResult cr;
    CryptedFileID idDir = ino;
    CryptedFileInfo info;
    CryptedDirEntry * pFirst, * pCur;
    DirContents * contents;

    logMsg(LOG_DEBUG, "opendir %ld", idDir);
        
    cr = coreQueryFileInfo(pVolume, idDir, &info);
    if (cr) { fuse_reply_err(req, core2sys(cr)); return; }

    contents = malloc(sizeof(DirContents));
    if (!contents) { fuse_reply_err(req, ENOMEM); return; }

    contents->len = 0;
    contents->buffer = 0;

    if (cr = filler(contents, idDir, ".")) goto barf;
    if (cr = filler(contents, info.idParent, "..")) goto barf;

    cr = coreQueryDirEntries(pVolume, idDir, &pFirst);
    if (cr) { fuse_reply_err(req, core2sys(cr)); return; }

    for (pCur = pFirst; pCur; pCur = pCur->pNext) {
        if (cr = filler(contents, pCur->idFile, pCur->pszName)) goto barf;
    }

    coreFreeDirEntries(pFirst);
    pFirst = 0;

    fi->fh = (unsigned long) contents;
    
    logMsg(LOG_DEBUG, "opendir result %p len %d", contents, contents->len);

    fuse_reply_open(req, fi);
    return;

 barf:
    if (pFirst) coreFreeDirEntries(pFirst);
    free(contents->buffer);
    free(contents);
    fuse_reply_err(req, core2sys(cr));
}


static void do_readdir(fuse_req_t req, fuse_ino_t ino,
    size_t size, off_t off, struct fuse_file_info * fi)
{
    DirContents * contents = (DirContents *) fi->fh;
    
    logMsg(LOG_DEBUG, "readdir offset %Ld size %d", off, size);
    logMsg(LOG_DEBUG, "readdir %p len %d", contents, contents->len);
    
    size_t outSize = 0;
    
    if (off < contents->len) {
        outSize = size;
        if (off + outSize > contents->len)
            outSize = contents->len - off;
    }
    
    logMsg(LOG_DEBUG, "readdir result %d", outSize);

    fuse_reply_buf(req, contents->buffer + off, outSize);
}


static void do_releasedir(fuse_req_t req, fuse_ino_t ino,
    struct fuse_file_info * fi)
{
    DirContents * contents = (DirContents *) fi->fh;
    logMsg(LOG_DEBUG, "releasedir");
    free(contents->buffer);
    free(contents);
    fuse_reply_err(req, 0);
}


int createFile(fuse_req_t req, fuse_ino_t parent,
    const char * pszName, mode_t mode,
    struct fuse_entry_param * entry)
{
    CoreResult cr;
    CryptedFileID idDir = parent, idFile;
    CryptedFileInfo info;

    logMsg(LOG_DEBUG, "create %ld %s %ho",
	idDir, pszName, mode);

    mode = mode & (CFF_IFMT | 07777);
    switch (mode & CFF_IFMT) {
        case CFF_IFREG: /* regular file */
        case CFF_IFLNK: /* symlink */
        case CFF_IFDIR: /* directory */
            break;
        default: /* device nodes are not supported */
            return ENOTSUP;
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

    fillEntryOut(entry, idFile, &info);

    return 0;
}


static void do_mknod(fuse_req_t req, fuse_ino_t parent,
    const char * name, mode_t mode, dev_t rdev)
{
    struct fuse_entry_param entry;
    int res = createFile(req, parent, name, mode, &entry);
    if (res)
        fuse_reply_err(req, res);
    else
        fuse_reply_entry(req, &entry);
}


static void do_mkdir(fuse_req_t req, fuse_ino_t parent,
    const char * name, mode_t mode)
{
    struct fuse_entry_param entry;
    int res = createFile(req, parent, name, mode | CFF_IFDIR, &entry);
    if (res)
        fuse_reply_err(req, res);
    else
        fuse_reply_entry(req, &entry);
}


int removeFile(CryptedFileID idDir, const char * pszName)
{
    CoreResult cr;
    CryptedFileID idFile;
    CryptedFileInfo info;
    CryptedDirEntry * pFirstEntry;

    cr = coreQueryIDFromPath(pVolume, idDir, pszName, &idFile, 0);
    if (cr) return core2sys(cr);

    cr = coreQueryFileInfo(pVolume, idFile, &info);
    if (cr) return core2sys(cr);

    if (CFF_ISDIR(info.flFlags)) {
	cr = coreQueryDirEntries(pVolume, idFile, &pFirstEntry);
	coreFreeDirEntries(pFirstEntry);
        if (cr) return core2sys(cr);
	if (pFirstEntry) return ENOTEMPTY;
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


static void do_unlink(fuse_req_t req, fuse_ino_t parent, const char * pszName)
{
    logMsg(LOG_DEBUG, "remove %ld %s", parent, pszName);

    int res = removeFile(parent, pszName);
    fuse_reply_err(req, res);
}


static void do_rmdir(fuse_req_t req, fuse_ino_t parent, const char * pszName)
{
    do_unlink(req, parent, pszName);
}


static void do_symlink(fuse_req_t req, const char * pszTarget,
    fuse_ino_t parent, const char * pszName)
{
    CoreResult cr;
    
    logMsg(LOG_DEBUG, "symlink %ld %s", parent, pszName);
    
    struct fuse_entry_param entry;
    int res = createFile(req, parent, pszName, 0777 | CFF_IFLNK, &entry);
    if (res)
        fuse_reply_err(req, res);
    else {
        cr = coreWriteSymlink(pVolume, entry.ino, pszTarget);
        if (cr) { fuse_reply_err(req, core2sys(cr)); return; }
        
        fuse_reply_entry(req, &entry);
    }
}


static void do_rename(fuse_req_t req, fuse_ino_t parent, const char * pszFrom,
    fuse_ino_t newparent, const char * pszTo)
{
    CoreResult cr;
    CryptedFileID idFrom = parent, idTo = newparent;
    int res;

    logMsg(LOG_DEBUG, "rename %ld %s %ld %s", idFrom, pszFrom, idTo, pszTo);

    /* Remove the to-name, if it exists. */
    res = removeFile(idTo, pszTo);
    if (res && res != ENOENT) { fuse_reply_err(req, res); return; }
    
    /* Rename. */
    cr = coreMoveDirEntry(pVolume,
        pszFrom, idFrom,
        pszTo, idTo);
    if (cr) { fuse_reply_err(req, core2sys(cr)); return; }

    /* Stamp the mtimes of the directories. */
    if ((cr = stampFile(idFrom)) ||
        ((idFrom != idTo) && (cr = stampFile(idTo))))
    {
        fuse_reply_err(req, core2sys(cr));
        return;
    }

    fuse_reply_err(req, 0);
}


static void do_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info * fi)
{
    CoreResult cr;
    CryptedFileID idFile = ino;
    CryptedFileInfo info;

    logMsg(LOG_DEBUG, "open %ld", idFile);

    cr = coreQueryFileInfo(pVolume, idFile, &info);
    if (cr) { fuse_reply_err(req, core2sys(cr)); return; }

    fuse_reply_open(req, fi);
}


static void do_read(fuse_req_t req, fuse_ino_t ino,
    size_t size, off_t off, struct fuse_file_info * fi)
{
    CoreResult cr;
    CryptedFileID idFile = ino;
    CryptedFilePos cbRead;

    logMsg(LOG_DEBUG, "read %ld %Ld %d", idFile, off, size);

    octet * buffer = malloc(size);
    if (!buffer) { fuse_reply_err(req, ENOMEM); return; }

    cr = coreReadFromFile(pVolume, idFile, off, size, buffer, &cbRead);
    logMsg(LOG_DEBUG, "error %d", cr);
    if (cr) { free(buffer); fuse_reply_err(req, core2sys(cr)); return; }

    fuse_reply_buf(req, buffer, cbRead);
    free(buffer);
}


static void do_write(fuse_req_t req, fuse_ino_t ino, const char * buf,
    size_t size, off_t off, struct fuse_file_info * fi)
{
    CoreResult cr;
    CryptedFileID idFile = ino;
    CryptedFilePos cbWritten;

    logMsg(LOG_DEBUG, "write %ld %Ld %d", idFile, off, size);

    cr = coreWriteToFile(pVolume, idFile, 
        off, size, buf, &cbWritten);
    if (cr) { fuse_reply_err(req, core2sys(cr)); return; }
    
    if (size != cbWritten) abort(); /* can't happen */
    
    cr = stampFile(idFile);
    if (cr) { fuse_reply_err(req, core2sys(cr)); return; }

    fuse_reply_write(req, cbWritten);
}


static void do_release(fuse_req_t req, fuse_ino_t ino,
    struct fuse_file_info * fi)
{
    commitVolume();
    fuse_reply_err(req, 0);
}


static void do_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
    struct fuse_file_info * fi)
{
    logMsg(LOG_DEBUG, "fsync");
    commitVolume();
    /* Maybe we should also sync the underlying files, but that's
       hard (e.g., how do we sync closed storage files?). */
    fuse_reply_err(req, 0);
}

static void do_statfs(fuse_req_t req)
{
    int res;
    struct statfs st;

    logMsg(LOG_DEBUG, "statfs");

    res = statfs(pSuperBlock->szBasePath, &st);
    if (res != 0) { fuse_reply_err(req, errno); return; }

    struct statfs st2;
    memset(&st2, 0, sizeof(struct statfs));
    st2.f_bsize = PAYLOAD_SIZE;
    st2.f_blocks = (st.f_bsize * (unsigned long long) st.f_blocks) / PAYLOAD_SIZE;
    st2.f_bfree = (st.f_bsize * (unsigned long long) st.f_bfree) / PAYLOAD_SIZE;
    st2.f_bavail = (st.f_bsize * (unsigned long long) st.f_bavail) / PAYLOAD_SIZE;
    st2.f_files = st.f_files; /* nonsensical */
    st2.f_ffree = st.f_ffree; /* idem */
    st2.f_namelen = PATH_MAX; /* !!! arbitrary */

    fuse_reply_statfs(req, &st2);
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

    //    logMsg(LOG_DEBUG, "flushing volume");

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


static void writeResult(CoreResult cr)
{
    write(fdRes[1], &cr, sizeof cr);
}


static struct fuse_lowlevel_ops aefs_oper = {
    .lookup     = do_lookup,
    .getattr    = do_getattr,
    .setattr    = do_setattr,
    .readlink   = do_readlink,
    .opendir    = do_opendir,
    .readdir    = do_readdir,
    .releasedir = do_releasedir,
    .mknod      = do_mknod,
    .mkdir      = do_mkdir,
    .unlink     = do_unlink,
    .rmdir      = do_rmdir,
    .symlink    = do_symlink,
    .rename     = do_rename,
    .open       = do_open,
    .read       = do_read,
    .write      = do_write,
    .release    = do_release,
    .fsync      = do_fsync,
    .statfs     = do_statfs,
};


/* Return true iff somebody unmounted us. */
static void run(char * pszPassPhrase)
{
    CryptedVolumeParms parms;
    CoreResult cr;
    int fd, fd2;
    pid_t pid;
 
    /* Daemonize. */
    if (!fDebug) {
        pid = fork();
        if (pid == -1) {
            logMsg(LOG_ERR, "%s: cannot fork: %s", 
                pszProgramName, strerror(errno));
            exit(1);
        }
        if (pid != 0) return;
        setsid();
        chdir("/");
        fd2 = open("/dev/null", O_RDWR);
        if (fd2 == -1) abort();
        dup2(fd2, 0);
        dup2(fd2, 1);
        dup2(fd2, 2);
    }
    
    coreSetDefVolumeParms(&parms);
    parms.fReadOnly = fReadOnly;
    parms.dirtyCallBack = dirtyCallBack;

    /* Read the superblock, initialize volume structures.  Note: we
       cannot call daemon() after coreReadSuperBlock(), since daemon()
       works by forking and children do not inherit file locks. */
retry:
    cr = coreReadSuperBlock(szBasePath, pszPassPhrase,
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
        goto exit;
    }

    /* FUSE expects that the root inode has index 1.  Fortunately
       that's the same as AEFS's default root inode number, but it
       doesn't have to be.  We should fix this (in FUSE, probably). */
    assert(pSuperBlock->idRoot == FUSE_ROOT_ID);

    pVolume = pSuperBlock->pVolume;

    /* `large_read' causes reads to be done in 64 KB chunks instead of
       4 KB (only works on kernel 2.4). */
    int error = 1;
    fd = fuse_mount(szMountPoint, "large_read");
    if (fd != -1) {

        struct fuse_session * session =
            fuse_lowlevel_new("debug", &aefs_oper, sizeof(aefs_oper), 0);

        if (session) {
            
            struct fuse_chan * channel = fuse_kern_chan_new(fd);
            if (channel) {
                error = 0;
                
                writeResult(CORERC_OK);

                /* !!! We really need a way to periodically call
                   commitVolume, as we did in the old FUSE-based
                   implementation.  Then do_release can go. */
    
                fuse_session_add_chan(session, channel);
                fuse_session_loop(session);
            }
            
            fuse_session_destroy(session);
        }
    }

    fuse_unmount(szMountPoint);
    
    commitVolume();
    coreDropSuperBlock(pSuperBlock);

    if (error) {
        writeResult(CORERC_SYS + SYS_UNKNOWN);
        goto exit;
    }

 exit:
    if (!fDebug) exit(0); /* daemon exit */
}


static void printUsage(int status)
{
   if (status)
      fprintf(stderr,
         "\nTry `%s --help' for more information.\n",
         pszProgramName);
   else {
      printf("\
Usage: %s [OPTION]... AEFS-PATH MOUNT-POINT\n\
Mount the AEFS volume stored in AEFS-PATH onto MOUNT-POINT.\n\
\n\
  -d, --debug        don't demonize, print debug info\n\
  -f, --force        force mount of dirty volume\n\
  -k, --key=KEY      use specified passphrase, do not ask\n\
  -r, --readonly     mount read-only\n\
      --help         display this help and exit\n\
      --version      output version information and exit\n\
\n\
" STANDARD_KEY_HELP "\
",
         pszProgramName);
   }
   exit(status);
}


int main(int argc, char * * argv)
{
    char szPassPhrase[1024], * pszOrigKey = 0;
    int c;
    char * pszPassPhrase = 0, * pszBasePath, * pszMountPoint;
    CoreResult cr;

    struct option const options[] = {
        { "help", no_argument, 0, 1 },
        { "version", no_argument, 0, 2 },
        { "debug", no_argument, 0, 'd' },
        { "key", required_argument, 0, 'k' },
        { "force", no_argument, 0, 'f' },
        { "readonly", no_argument, 0, 'r' },
        { 0, 0, 0, 0 } 
    };      

    sysInitPRNG();

    /* Parse the arguments. */

    pszProgramName = argv[0];

    while ((c = getopt_long(argc, argv, "dfk:r", options, 0)) != EOF) {
        switch (c) {
            case 0:
                break;

            case 1: /* --help */
                printUsage(0);
                break;

            case 2: /* --version */
                printf("aefsfuse - %s\n", AEFS_VERSION);
                exit(0);
                break;

            case 'd': /* --debug */
                fDebug = true;
                break;

            case 'k': /* --key */
                pszPassPhrase = pszOrigKey = optarg;
                break;

            case 'f': /* --force */
                fForceMount = true;
                break;

            case 'r': /* --readonly */
                fReadOnly = true;
                break;

            default:
                printUsage(1);
        }
    }

    if (optind != argc - 2) {
        fprintf(stderr, "%s: missing or too many parameters\n", pszProgramName);
        printUsage(1);
    }

    pszBasePath = argv[optind++];
    pszMountPoint = argv[optind++];

    /* Create a pipe for talking to the child. */
    if (pipe(fdRes) == -1) {
        fprintf(stderr, "%s: cannot create a pipe: %s\n", 
            pszProgramName, strerror(errno));
        return 1;
    }

    /* Expand the base path. */
    if (!realpath(pszBasePath, szBasePath)) {
        fprintf(stderr, "%s: cannot expand path: %s\n", 
            pszProgramName, strerror(errno));
        return 1;
    }
    strcat(szBasePath, "/");

    /* Expand the mount point. */
    if (!realpath(pszMountPoint, szMountPoint)) {
        fprintf(stderr, "%s: cannot expand path: %s\n", 
            pszProgramName, strerror(errno));
        return 1;
    }

    /* Passphrase specified in the environment? */
    if (!pszPassPhrase) {
        pszPassPhrase = getenv("AEFS_PASSPHRASE");
    }

    /* Ask the user to enter the passphrase, if it wasn't specified
       with "-k". */
    if (!pszPassPhrase) {
        pszPassPhrase = szPassPhrase;
        if (readPhrase("passphrase: ", sizeof(szPassPhrase), szPassPhrase)) {
            fprintf(stderr, "%s: error reading passphrase\n", pszProgramName);
            return 1;
        }
    }

    run(pszPassPhrase);
    
    memset(pszPassPhrase, 0, strlen(pszPassPhrase)); /* burn */

    /* Read the result. */
    if (read(fdRes[0], &cr, sizeof(cr)) != sizeof(cr)) {
        fprintf(stderr, "%s: cannot read daemon result: %s\n",
            pszProgramName, strerror(errno));
        return 1;
    }

    if (cr) {
        fprintf(stderr, "%s: %s\n", pszProgramName, core2str(cr));
        return 1;
    }

    return 0;
}
