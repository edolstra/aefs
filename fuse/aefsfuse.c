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

#include "aefsfuse.h"


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


static void storeAttr(CryptedFileID idFile, CryptedFileInfo * info,
    struct fuse_attr * attr)
{
    memset(attr, 0, sizeof(struct fuse_attr));
    attr->ino = idFile;
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
    attr->atimensec = attr->mtimensec = attr->ctimensec = 0;
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


static void fillEntryOut(struct fuse_entry_out * out,
    CryptedFileID idFile, CryptedFileInfo * info, struct fuse_attr * attr)
{
    out->nodeid = idFile;
    out->generation = generation++;
    out->entry_valid = 1; /* sec */
    out->entry_valid_nsec = 0;
    out->attr_valid = 1; /* sec */
    out->attr_valid_nsec = 0;
    storeAttr(idFile, info, attr);
}


int do_lookup(struct fuse_in_header * in, char * name, struct fuse_entry_out * out)
{
    CoreResult cr;
    CryptedFileID idDir = in->nodeid, idFile;
    CryptedFileInfo info;

    logMsg(LOG_DEBUG, "lookup %ld %s", idDir, name);

    cr = coreQueryIDFromPath(pVolume, idDir, name, &idFile, 0);
    if (cr) return core2sys(cr);

    cr = coreQueryFileInfo(pVolume, idFile, &info);
    if (cr) return core2sys(cr);

    fillEntryOut(out, idFile, &info, &out->attr);
    
    return 0;
}


int do_setattr(struct fuse_in_header * in, struct fuse_setattr_in * arg, 
    struct fuse_attr_out * out)
{
    CoreResult cr;
    CryptedFileID idFile = in->nodeid;
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

    if (arg->valid & FATTR_MTIME) {
	logMsg(LOG_DEBUG, "set mtime %ld", arg->attr.mtime);
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

    storeAttr(idFile, &info, &out->attr);

    return 0;
}


int do_getattr(struct fuse_in_header * in, struct fuse_attr_out * out)
{
    CoreResult cr;
    CryptedFileID idFile = in->nodeid;
    CryptedFileInfo info;

    logMsg(LOG_DEBUG, "getattr %ld", idFile);

    cr = coreQueryFileInfo(pVolume, idFile, &info);
    if (cr) return core2sys(cr);

    storeAttr(idFile, &info, &out->attr);

    return 0;
}


int do_readlink(struct fuse_in_header * in, char * outbuf)
{
    CoreResult cr;
    CryptedFileID idLink = in->nodeid;
    CryptedFileInfo info;
    CryptedFilePos cbRead;

    logMsg(LOG_DEBUG, "readlink %ld", idLink);

    cr = coreQueryFileInfo(pVolume, idLink, &info);
    if (cr) return core2sys(cr);

    if (!CFF_ISLNK(info.flFlags)) return -EINVAL;
    if (info.cbFileSize >= PATH_MAX) return -ENAMETOOLONG;

    cr = coreReadFromFile(pVolume, idLink, 0,
        info.cbFileSize, (octet *) outbuf, &cbRead);
    if (cr) return core2sys(cr);
    outbuf[info.cbFileSize] = 0;

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
    if (res != reclen) {
        perror("writing directory file");
        return -EIO;
    }
    return 0;
}


int do_getdir(struct fuse_in_header * in, struct fuse_getdir_out * out)
{
    CoreResult cr;
    CryptedFileID idDir = in->nodeid;
    CryptedFileInfo info;
    CryptedDirEntry * pFirst, * pCur;

    logMsg(LOG_DEBUG, "getdir %ld", idDir);

    out->fd = open("/tmp/fuse_tmp", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (out->fd == -1) return -errno;
    unlink("/tmp/fuse_tmp");

    cr = coreQueryFileInfo(pVolume, idDir, &info);
    if (cr) return core2sys(cr);

    filler(out->fd, idDir, ".");
    filler(out->fd, info.idParent, "..");

    cr = coreQueryDirEntries(pVolume, idDir, &pFirst);
    if (cr) return core2sys(cr);

    for (pCur = pFirst; pCur; pCur = pCur->pNext) {
        filler(out->fd, pCur->idFile, pCur->pszName);
    }

    coreFreeDirEntries(pFirst); /* !!! */

    return 0;
}


int createFile(CryptedFileID idDir, char * pszName,
    unsigned int mode, unsigned int rdev,
    struct fuse_entry_out * out)
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

    fillEntryOut(out, idFile, &info, &out->attr);

    return 0;
}


int do_mknod(struct fuse_in_header * in, struct fuse_mknod_in * arg, 
    char * pszName, struct fuse_entry_out * out)
{
    return createFile(in->nodeid, pszName, arg->mode, arg->rdev, out);
}


int do_mkdir(struct fuse_in_header * in, struct fuse_mkdir_in * arg,
    char * pszName, struct fuse_entry_out * out)
{
    return createFile(in->nodeid, pszName, arg->mode | CFF_IFDIR, 0, out);
}


int removeFile(CryptedFileID idDir, char * pszName)
{
    CoreResult cr;
    CryptedFileID idFile;
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



int do_remove(struct fuse_in_header * in, char * pszName)
{
    return removeFile(in->nodeid, pszName);
}


int do_symlink(struct fuse_in_header * in, 
    char * pszName, char * pszTarget, struct fuse_entry_out * out)
{
    CoreResult cr;
    CryptedFilePos cbWritten;
    int res;

    res = createFile(in->nodeid, pszName, 
        0777 | CFF_IFLNK, 0, out);
    if (res) return res;
    
    logMsg(LOG_DEBUG, "symlink %ld %s", out->nodeid, pszTarget);

    cr = coreWriteToFile(pVolume, out->nodeid, 0,
        strlen(pszTarget), (octet *) pszTarget, &cbWritten);
    if (cr) return core2sys(cr);

    return 0;
}


int do_rename(struct fuse_in_header * in, struct fuse_rename_in * arg,
    char * pszFrom, char * pszTo)
{
    CoreResult cr;
    CryptedFileID idFrom = in->nodeid, idTo = arg->newdir;
    int res;

    logMsg(LOG_DEBUG, "rename %ld %s %ld %s", idFrom, pszFrom, idTo, pszTo);

    /* Remove the to-name, if it exists. */
    res = removeFile(idTo, pszTo);
    if (res && res != -ENOENT) return res;
    
    /* Rename. */
    cr = coreMoveDirEntry(pVolume,
        pszFrom, idFrom,
        pszTo, idTo);
    if (cr) return core2sys(cr);

    /* Stamp the mtimes of the directories. */
    if (cr = stampFile(idFrom)) return core2sys(cr);
    if ((idFrom != idTo) && (cr = stampFile(idTo))) return core2sys(cr);

    return 0;
}


int do_link(struct fuse_in_header * in, struct fuse_link_in * arg,
    char * pszName, struct fuse_entry_out * out)
{
    return -ENOTSUP; /* !!! */
}


int do_open(struct fuse_in_header * in, struct fuse_open_in * arg)
{
    CoreResult cr;
    CryptedFileID idFile = in->nodeid;
    CryptedFileInfo info;

    logMsg(LOG_DEBUG, "open %ld", idFile);

    cr = coreQueryFileInfo(pVolume, idFile, &info);
    if (cr) return core2sys(cr);

    return 0;
}


int do_read(struct fuse_in_header * in, struct fuse_read_in * arg, char * outbuf)
{
    CoreResult cr;
    CryptedFileID idFile = in->nodeid;
    CryptedFilePos cbRead;

    logMsg(LOG_DEBUG, "read %ld %Ld %d", idFile, arg->offset, arg->size);

    cr = coreReadFromFile(pVolume, idFile, arg->offset, arg->size, outbuf, &cbRead);
    if (cr) return core2sys(cr);

    return cbRead;
}


int do_write(struct fuse_in_header * in, struct fuse_write_in * arg,
    void * pData, struct fuse_write_out * out)
{
    CoreResult cr;
    CryptedFileID idFile = in->nodeid;
    CryptedFilePos cbWritten;
    int res = 0;

    logMsg(LOG_DEBUG, "write %ld %Ld %d", idFile, arg->offset, arg->size);

    cr = coreWriteToFile(pVolume, idFile, 
        arg->offset, arg->size, pData, &cbWritten);
    out->size = cbWritten;
    if (cr) res = core2sys(cr);
    else if (arg->size != cbWritten) abort(); /* can't happen */
    else {
        cr = stampFile(idFile);
        res = core2sys(cr);
    }

    return 0;
}


int do_statfs(struct fuse_in_header * in, struct fuse_statfs_out * out)
{
    int res;
    struct statfs st;
    unsigned long long cbTotal, cbFree;

    logMsg(LOG_DEBUG, "statfs");

    res = statfs(pSuperBlock->szBasePath, &st);
    if (res != 0) return -errno;

    cbTotal = st.f_bsize * (unsigned long long) st.f_blocks;
    cbFree = st.f_bsize * (unsigned long long) st.f_bfree;
    
    out->st.bsize = PAYLOAD_SIZE;
    out->st.blocks = cbTotal / PAYLOAD_SIZE; /* nonsensical */
    out->st.bfree = out->st.bavail = cbFree / PAYLOAD_SIZE;
    out->st.files = st.f_files; /* nonsensical */
    out->st.ffree = st.f_ffree; /* idem */
    out->st.namelen = 1024; /* !!! arbitrary */

    return 0;
}


int do_fsync(struct fuse_in_header * in, struct fuse_fsync_in * arg)
{
    logMsg(LOG_DEBUG, "fsync");
    commitVolume();
    /* Maybe we should also sync the underlying files, but that's
       hard (e.g., how do we sync closed storage files?). */
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


static void unmount()
{
    if (fork() == 0) {
        execlp("fusermount", "fusermount", "-u", szMountPoint, 0);
        exit(0);
    }
}


static void writeResult(CoreResult cr)
{
    write(fdRes[1], &cr, sizeof cr);
}


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

    /* `large_read' causes reads to be done in 64 KB chunks instead of
       4 KB (only works on kernel 2.4). */
    fd = fuse_mount(szMountPoint, "large_read");
    if (fd == -1) {
        writeResult(CORERC_SYS + SYS_UNKNOWN);
        unmount();
        goto exit;
    }
    setFuseFD(fd);
    
    writeResult(CORERC_OK);
    
    pVolume = pSuperBlock->pVolume;

    if (!runLoop()) 
        unmount();

    commitVolume();
    coreDropSuperBlock(pSuperBlock);

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
