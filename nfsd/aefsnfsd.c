/* aefsnfsd.c -- NFS server front-end to AEFS.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: aefsnfsd.c,v 1.24 2001/09/23 13:30:18 eelco Exp $

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

#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#define PORTMAP /* enables backward compatibility under Solaris */
#include <rpc/rpc.h>
#include <syslog.h>

#include "getopt.h"

#include "sysdep.h"
#include "ciphertable.h"
#include "corefs.h"
#include "coreutils.h"
#include "superblock.h"

#include "nfs_prot.h"
#include "mount.h"
#include "aefsctrl.h"


#define NOTIMPL assert(0); return 0;

#define MAX_FILESYSTEMS 1024



void nfs_program_2(struct svc_req * rqstp, SVCXPRT * transp);
void mountprog_1(struct svc_req * rqstp, SVCXPRT * transp);
void nlm_prog_1(struct svc_req * rqstp, SVCXPRT * transp);
void aefsctrl_program_1(struct svc_req * rqstp, SVCXPRT * transp);


typedef unsigned int fsid;

typedef struct {
        SuperBlock * pSuperBlock;
        int uid, gid;
        unsigned int cRefs;
        bool fLazyWrite;
} Filesystem;


Filesystem * apFilesystems[MAX_FILESYSTEMS];


typedef struct {
        int uid, gid;
        int gids[NGRPS];
} User;



#define GET_SUPERBLOCK(fs) (apFilesystems[fs]->pSuperBlock)
#define GET_VOLUME(fs) (apFilesystems[fs]->pSuperBlock->pVolume)


char * pszProgramName;

int voidthing;
#define VOIDOBJ ((void *) &voidthing)

bool fDebug = false;

bool fTerminate = false;


/* Write a message to syslog. */
static void logMsg(int level, char * pszMsg, ...)
{
    va_list args;
    if ((level == LOG_DEBUG) && !fDebug) return;
    va_start(args, pszMsg);
    if (fDebug) {
        vfprintf(stderr, pszMsg, args);
        fprintf(stderr, "\n");
        fflush(stderr);
    } else {
        vsyslog(level, pszMsg, args);
    }
    va_end(args);
}


/* Construct an NFS file handle from a file system identifier and a
   file identifier. */
static void encodeFH(nfs_fh * fh, fsid fs, CryptedFileID id)
{
    assert((fs < MAX_FILESYSTEMS) && apFilesystems[fs]);
    ((uint32 *) fh->data) [0] = htonl(id);
    ((uint32 *) fh->data) [1] = htonl(fs);
}


/* Deconstruct an NFS file handle into a file system identifier and a
   file identifier. */
static nfsstat decodeFH(nfs_fh * fh, fsid * pfs, CryptedFileID * pid)
{
    *pid = ntohl(((uint32 *) fh->data) [0]);
    *pfs = ntohl(((uint32 *) fh->data) [1]);
    if ((*pfs >= MAX_FILESYSTEMS) || !apFilesystems[*pfs])
        return NFSERR_STALE; /* actually, not stale but invalid */
    else
        return NFS_OK;
}


/* Canonicalize a path: change backslashes into slashes, remove
   redundant slashes (foo//bar -> foo/bar) and add a slash at the
   end. */
static void canonicalizePath(char * src, char * dst)
{
    bool inSep = false;

    while (*src) {
        if ((*src == '/') || (*src == '\\')) {
            if (!inSep) {
                *dst++ = '/';
                inSep = true;
            }
        } else {
            inSep = false;
            *dst++ = *src;
        }
        src++;
    }

    if (!inSep) *dst++ = '/';
    *dst = 0;
}


/* Translate a core error code into an NFS error code. */
static nfsstat core2nfsstat(CoreResult cr)
{
    switch (cr) {
        case CORERC_OK: return NFS_OK;
        case CORERC_FILE_NOT_FOUND: return NFSERR_NOENT;
        case CORERC_NOT_ENOUGH_MEMORY: return 12; /* ENOMEM */
        case CORERC_FILE_EXISTS: return NFSERR_EXIST;
        case CORERC_INVALID_PARAMETER: abort();
        case CORERC_INVALID_NAME: return 22; /* EINVAL */
        case CORERC_BAD_CHECKSUM: return NFSERR_IO;
        case CORERC_BAD_INFOSECTOR: return NFSERR_IO;
        case CORERC_NOT_DIRECTORY: return NFSERR_NOTDIR;
        case CORERC_BAD_DIRECTORY: return NFSERR_IO;
        case CORERC_BAD_TYPE: return NFSERR_IO;
        case CORERC_BAD_EAS: return NFSERR_IO;
        case CORERC_CACHE_OVERFLOW: abort();
        case CORERC_READ_ONLY: return NFSERR_ROFS;
        case CORERC_ISF_CORRUPT: return NFSERR_IO;
        case CORERC_ID_EXISTS: return NFSERR_IO;
        default:
            if (IS_CORERC_SYS(cr)) return NFSERR_IO;
            fprintf(stderr, "unexpected corefs error %d\n", cr);
            return NFSERR_PERM;
    }
}


/* Smash user and group IDs, i.e. replace the actual UID and GID of
   the file by the ones specified when the file system was added,
   unless they were -1. */
static void smashUGID(fsid id, CryptedFileInfo * pInfo)
{
    if (apFilesystems[id]->uid != -1)
        pInfo->uid = apFilesystems[id]->uid;
    if (apFilesystems[id]->gid != -1)
        pInfo->gid = apFilesystems[id]->gid;
}


/* Store file attributes in a NFS fattr structure. */
static nfsstat storeAttr(fattr * pAttr, fsid fs, CryptedFileID idFile)
{
    CoreResult cr;
    CryptedFileInfo info;
    
    cr = coreQueryFileInfo(GET_VOLUME(fs), idFile, &info);
    if (cr) return core2nfsstat(cr);

    smashUGID(fs, &info);

    switch (info.flFlags & CFF_IFMT) {
        case CFF_IFREG: pAttr->type = NFREG; break;
        case CFF_IFDIR: pAttr->type = NFDIR; break;
        case CFF_IFLNK: pAttr->type = NFLNK; break;
        default: pAttr->type = NFNON;
    }

    pAttr->mode = info.flFlags;
    pAttr->nlink = info.cRefs;
    pAttr->uid = info.uid;
    pAttr->gid = info.gid;
    pAttr->size = info.cbFileSize;
    pAttr->blocksize = SECTOR_SIZE;
    pAttr->rdev = 0;
    pAttr->blocks = info.csSet;
    pAttr->fsid = 0;
    pAttr->fileid = idFile;
    pAttr->atime.seconds = info.timeAccess;
    pAttr->atime.useconds = 0;
    pAttr->mtime.seconds = info.timeWrite;
    pAttr->mtime.useconds = 0;
    pAttr->ctime.seconds = info.timeAccess; /* !!! */
    pAttr->ctime.useconds = 0;

    return NFS_OK;
}


/* Get the parent directory of the specified directory. */
static nfsstat getParentDir(fsid fs, CryptedFileID idDir, 
    CryptedFileID * pidParent)
{
    CoreResult cr;
    CryptedFileInfo info;

    *pidParent = 0;
    
    cr = coreQueryFileInfo(GET_VOLUME(fs), idDir, &info);
    if (cr) return core2nfsstat(cr);

    *pidParent = info.idParent;
    
    return NFS_OK;
}


typedef struct {
        fsid fs;
        CryptedFileID idDir;
        unsigned int cEntries;
        CryptedDirEntry * pFirst;
        CryptedDirEntry * * papSortedByID;
} DirCacheEntry;


/* Free a directory cache entry. */
static void freeDirCacheEntry(DirCacheEntry * pEntry)
{
    if (pEntry->pFirst) coreFreeDirEntries(pEntry->pFirst);
    if (pEntry->papSortedByID) free(pEntry->papSortedByID);
    free(pEntry);
}


#define DIRCACHE_SIZE 32
static DirCacheEntry * dirCache[DIRCACHE_SIZE];


static int compareIDs(const void * p1, const void * p2)
{
    return
        (* * (CryptedDirEntry * *) p1).idFile -
        (* * (CryptedDirEntry * *) p2).idFile;
}


/* Return a directory cache entry for the specified directory.  This
   may invalidate all pointers into the directory cache that the
   caller may have. */
static nfsstat queryDirEntries(fsid fs, CryptedFileID idDir,
    DirCacheEntry * * ppEntry)
{
    unsigned int i, j;
    DirCacheEntry * pEntry;
    CryptedDirEntry * pCur;
    CoreResult cr;
    
    /* Perhaps the directory is already in the cache? */
    for (i = 0; i < DIRCACHE_SIZE; i++)
        if (dirCache[i] && (dirCache[i]->fs == fs) && 
            (dirCache[i]->idDir == idDir)) {
            /* Move pEntry to the front of the MRU list. */
            pEntry = dirCache[i];
            for (j = i; j > 0; j--)
                dirCache[j] = dirCache[j - 1];
            dirCache[0] = pEntry;
            *ppEntry = pEntry;
            return NFS_OK;
        }

    /* No.  Read the directory and add it to the cache. */

    pEntry = malloc(sizeof(DirCacheEntry)); /* !!! */
    if (!pEntry) return 12; /* ENOMEM */

    pEntry->fs = fs;
    pEntry->idDir = idDir;
    pEntry->pFirst = 0;
    pEntry->papSortedByID = 0;

    cr = coreQueryDirEntries(GET_VOLUME(fs), idDir,
        &pEntry->pFirst);
    if (cr) {
        freeDirCacheEntry(pEntry);
        return core2nfsstat(cr);
    }

    for (pCur = pEntry->pFirst, pEntry->cEntries = 0; 
         pCur; 
         pCur = pCur->pNext, pEntry->cEntries++) ;

    pEntry->papSortedByID = malloc(pEntry->cEntries * 
        sizeof(CryptedDirEntry *));
    if (!pEntry->papSortedByID) {
        freeDirCacheEntry(pEntry);
        return 12; /* ENOMEM */
    }

    for (pCur = pEntry->pFirst, i = 0; 
         pCur; 
         pCur = pCur->pNext, i++)
        pEntry->papSortedByID[i] = pCur;

    qsort(pEntry->papSortedByID, pEntry->cEntries,
        sizeof(CryptedDirEntry *), compareIDs);
    
    if (dirCache[DIRCACHE_SIZE - 1])
        freeDirCacheEntry(dirCache[DIRCACHE_SIZE - 1]);
    for (j = DIRCACHE_SIZE - 1; j > 0; j--)
        dirCache[j] = dirCache[j - 1];

    dirCache[0] = pEntry;

    *ppEntry = pEntry;
    return NFS_OK;
}


/* Remove the cached contents of a directory.  Must be called when the
   directory has changed.  idDir set to 0 will flush all directories
   on the file system. */
static void dirtyDir(fsid fs, CryptedFileID idDir)
{
    unsigned int i, j;
    for (i = 0; i < DIRCACHE_SIZE; i++)
        if (dirCache[i] && (dirCache[i]->fs == fs) &&
            (!idDir || (dirCache[i]->idDir == idDir))) 
        {
            freeDirCacheEntry(dirCache[i]);
            for (j = i + 1; j < DIRCACHE_SIZE; j++)
                dirCache[j - 1] = dirCache[j];
	    dirCache[DIRCACHE_SIZE - 1] = 0;
	}
}


/* Stamp a file's mtime. */
static nfsstat stampFile(fsid fs, CryptedFileID idFile)
{
    CoreResult cr;
    CryptedFileInfo info;

    /* Update the directory's last-written (mtime) timestamp. */
    cr = coreQueryFileInfo(GET_VOLUME(fs), idFile, &info);
    if (cr) return core2nfsstat(cr);
    
    info.timeWrite = time(0);
    
    cr = coreSetFileInfo(GET_VOLUME(fs), idFile, &info);
    if (cr) return core2nfsstat(cr);

    return NFS_OK;
}


/* Check that the caller is permitted to talk to us.  Fill in the
   credentials structure. */
static nfsstat authCaller(struct svc_req * rqstp, User * pUser)
{
    struct sockaddr_in * caller;
    struct authunix_parms * cred;
    unsigned int i;

    caller = svc_getcaller(rqstp->rq_xprt);
    if (!caller) return NFSERR_PERM;

    /* The call should come from `localhost'. */
    if (ntohl(caller->sin_addr.s_addr) != INADDR_LOOPBACK)
        return NFSERR_PERM;
    
    /* The call should come from a privileged port. */
    if (ntohs(caller->sin_port) >= IPPORT_RESERVED)
        return NFSERR_PERM;

    /* The call should have Unix authentication info. */
    if (rqstp->rq_cred.oa_flavor != AUTH_UNIX)
        return NFSERR_PERM;

    cred = (struct authunix_parms *) rqstp->rq_clntcred;
    pUser->uid = cred->aup_uid;
    pUser->gid = cred->aup_gid;
    for (i = 0; i < NGRPS; i++)
        pUser->gids[i] = cred->aup_gids[i];

    return NFS_OK;
}


static bool isInGroup(User * pUser, int gid)
{
    unsigned int i;
    if (gid == pUser->gid) return 1;
    for (i = 0; i < NGRPS; i++)
        if (gid == pUser->gids[i]) return true;
    return false;
}


/* Does the user have the required permission to a file, based on the
   file info structure?  smashUGID() must have been called prior to
   this. */
static int havePerm(unsigned int what, User * pUser, 
    CryptedFileInfo * pInfo)
{
    unsigned int flFlags = pInfo->flFlags;
    /* As a special exception, allow writing even if the caller is the
       owner but has no write permission.  This is the only way we can
       support the fucked-up Unix semantics that you can write to a
       file created by creat() even when the write bits are
       cleared. */
    flFlags |= 0200;
    return
        ((pInfo->uid == pUser->uid) && 
            ((flFlags & (what << 6)) == (what << 6))) ||
        (isInGroup(pUser, pInfo->gid) && 
            ((flFlags & (what << 3)) == (what << 3))) ||
        ((flFlags & what) == what) ||
        (pUser->uid == 0) /* root */;
}


/* Does the user have the required permission to a file? */
static nfsstat havePerm2(unsigned int what, User * pUser, fsid fs,
    CryptedFileID idFile)

{
    CoreResult cr;
    CryptedFileInfo info;
    
    cr = coreQueryFileInfo(GET_VOLUME(fs), idFile, &info);
    if (cr) return core2nfsstat(cr);

    smashUGID(fs, &info);
    
    return havePerm(what, pUser, &info) ? NFS_OK : NFSERR_PERM;
}


/* Called by corefs whenever it marks a sector as dirty. */
static void dirtyCallBack(CryptedVolume * pVolume, bool fDirty)
{
    CoreResult cr;
    Filesystem * pFS = apFilesystems[(fsid)
        coreQueryVolumeParms(pVolume)->pUserData];
    
    logMsg(LOG_DEBUG, "dirtyCallBack, fDirty=%d", fDirty);

    if (fDirty) { /* the volume now has dirty sectors */

        if (!(pFS->pSuperBlock->flFlags & SBF_DIRTY)) {
            pFS->pSuperBlock->flFlags |= SBF_DIRTY;
            cr = coreWriteSuperBlock(pFS->pSuperBlock,
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
static nfsstat commitVolume(fsid fs)
{
    CoreResult cr;

    logMsg(LOG_DEBUG, "flushing volume");

    /* Flush dirty data. */
    cr = coreFlushVolume(GET_VOLUME(fs));
    if (cr) {
        logMsg(LOG_ERR, "error flushing volume, cr=%d", cr);
        return core2nfsstat(cr);
    }

    /* In the OS/2 daemon, we close the storage files at this
       point.  That's because the OS/2 kernel doesn't commit file
       size changes until the file is closed, so there is an
       indefinitely long time window in which data might be lost
       due to a system failure.  But Unices seem to be a bit more
       sensible in this regard, so we don't do that here. */

    /* Clear the dirty bit in the superblock. */
    if (GET_SUPERBLOCK(fs)->flFlags & SBF_DIRTY) {
        GET_SUPERBLOCK(fs)->flFlags &= ~SBF_DIRTY;
        cr = coreWriteSuperBlock(GET_SUPERBLOCK(fs),
            CWS_NOWRITE_SUPERBLOCK1);
        if (cr) {
            logMsg(LOG_ERR, "error clearing dirty flag, cr=%d", cr);
            GET_SUPERBLOCK(fs)->flFlags |= SBF_DIRTY; /* retry */
            return core2nfsstat(cr);
        }
    }

    return NFS_OK;
}


/* Commit all volumes. */
static void commitAll()
{
    unsigned int i;
    for (i = 0; i < MAX_FILESYSTEMS; i++)
        if (apFilesystems[i] && apFilesystems[i]->fLazyWrite)
            commitVolume(i);
}


/* Should be called when the volume has changed.  If lazy writing is
   enabled, flush all dirty data.  Otherwise, do nothing. */
static nfsstat volumeDirty(fsid fs)
{
    if (!apFilesystems[fs]->fLazyWrite) 
        return commitVolume(fs);
    else
        return NFS_OK;
}


/* Create a socket and bind it to the loopback interface. */
static int makeSocket(int protocol)
{
    int s, res;
    struct sockaddr_in addr;
    
    s = socket(
        PF_INET,
        protocol == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM,
        protocol);
    if (s == -1) return -1;
        
    addr.sin_family = AF_INET;
    addr.sin_port = htons(AEFSNFSD_DEF_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    memset(addr.sin_zero, 0, sizeof(addr.sin_zero));
    res = bind(s, (struct sockaddr *) &addr, sizeof(addr));
    if (res == -1) return -1;

    return s;
}


/* Create (and register) our RPC services on the given transport
   protocol. */
static SVCXPRT * createAndRegister(int protocol, bool fRegister)
{
    SVCXPRT * transp;
    int s;
    int reg = fRegister ? protocol : 0;
    
    s = makeSocket(protocol);
    if (s == -1) {
        fprintf(stderr, "%s: cannot bind to port %d: %s",
            pszProgramName, AEFSNFSD_DEF_PORT, strerror(errno));
        return 0;
    }

    if (protocol == IPPROTO_UDP) 
        transp = svcudp_create(s);
    else
        transp = svctcp_create(s, 0, 0);
    if (transp == NULL) {
        fprintf(stderr, "%s: cannot create service\n", pszProgramName);
        return 0;
    }

    if (!svc_register(transp, NFS_PROGRAM, NFS_VERSION, 
            nfs_program_2, reg) ||
        !svc_register(transp, MOUNTPROG, MOUNTVERS, 
            mountprog_1, reg) ||
        !svc_register(transp, AEFSCTRL_PROGRAM, AEFSCTRL_VERSION_1,
            aefsctrl_program_1, reg)
        )
    {
        fprintf(stderr,
            "%s: unable to register services\n",
            pszProgramName);
        return 0;
    }

    return transp;
}


static void printUsage(int status)
{
   if (status)
      fprintf(stderr,
         "\nTry `%s --help' for more information.\n",
         pszProgramName);
   else {
      printf("\
Usage: %s [OPTION]... PATH\n\
Start the AEFS NFS server.\n\
\n\
      --help         display this help and exit\n\
      --version      output version information and exit\n\
  -d, --debug        don't demonize, print debug info\n\
  -l, --lock         lock daemon memory (disable swapping)\n\
  -r, --register     register with portmapper\n\
",
         pszProgramName);
   }
   exit(status);
}


/* Called when a TERM or INT signal occurs.  Tell the main loop in
   run() to exit.  Note that this assumes that signal() will return
   with a EINTR error.  If that's not the behaviour on the current
   system, we have to wait until the next time-out. */
static void sigHandler(int signo)
{
    fTerminate = true;
}


/* Process RPC requests.  This is what svc_run() does, but we
   implement our own loop so that we can do lazy writing. */
static int run()
{
    fd_set readfds;
    struct timeval timeout;
    int err = 0, max, res, i;
    time_t maxAge = 5, timeFlush = time(0), timeCur;
    struct sigaction act, oldact1, oldact2;

    act.sa_handler = sigHandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;

    if ((sigaction(SIGTERM, &act, &oldact1) == -1) ||
        (sigaction(SIGINT, &act, &oldact2) == -1)) {
        logMsg(LOG_ALERT, "cannot install signal handlers: %s",
            strerror(errno));
        return 1;
    }

    while (!fTerminate) {
        readfds = svc_fdset;
        for (i = max = 0; i < FD_SETSIZE; i++)
            if (FD_ISSET(i, &readfds)) max = i;
        
        /* Lazy writer.  Should we flush now?  Determine the time-out
           for select(). */
        timeCur = time(0);
        if (timeCur >= timeFlush + maxAge) {
            logMsg(LOG_DEBUG, "flushing everything");
            commitAll();
            timeFlush = timeCur;
            timeout.tv_sec = maxAge;
        } else
            timeout.tv_sec = timeFlush + maxAge - timeCur;
        timeout.tv_usec = 0;

        /* Sleep until we get some input, or until we should flush. */
        res = select(max + 1, &readfds, 0, 0, &timeout);
        if (res == -1 && errno != EINTR) {
            logMsg(LOG_ALERT, "error from select: %s",
                strerror(errno));
            err = 1;
            break;
        }

        if (res > 0) {
            svc_getreqset(&readfds);
        }
    }

    sigaction(SIGTERM, &oldact1, 0);
    sigaction(SIGINT, &oldact2, 0);

    return err;
}


int main(int argc, char * * argv)
{
    unsigned int i;
    int c;
    SVCXPRT * udp, * tcp;
    bool fRegister = false;
        
    struct option const options[] = {
        { "help", no_argument, 0, 1 },
        { "version", no_argument, 0, 2 },
        { "debug", no_argument, 0, 'd' },
        { 0, 0, 0, 0 } 
    };      

    /* Parse the arguments. */
   
    pszProgramName = argv[0];

    while ((c = getopt_long(argc, argv, "dlr", options, 0)) != EOF) {
        switch (c) {
            case 0:
                break;

            case 1: /* --help */
                printUsage(0);
                break;

            case 2: /* --version */
                printf("aefsnfsd - %s\n", AEFS_VERSION);
                exit(0);
                break;

            case 'd': /* --debug */
                fDebug = true;
                break;

            case 'l': /* --lock */
                sysLockMem();
                break;

            case 'r': /* --register */
                fRegister = true;
                break;

            default:
                printUsage(1);
        }
    }

    if (optind != argc) {
        fprintf(stderr, "%s: missing or too many parameters\n", pszProgramName);
        printUsage(1);
    }

    sysInitPRNG();

    for (i = 0; i < MAX_FILESYSTEMS; i++)
        apFilesystems[i] = 0;

    for (i = 0; i < DIRCACHE_SIZE; i++)
        dirCache[i] = 0;

    (void) pmap_unset(NFS_PROGRAM, NFS_VERSION);
    (void) pmap_unset(MOUNTPROG, MOUNTVERS);
    (void) pmap_unset(AEFSCTRL_PROGRAM, AEFSCTRL_VERSION_1);

    if (!(udp = createAndRegister(IPPROTO_UDP, fRegister))) return 1;
    if (!(tcp = createAndRegister(IPPROTO_TCP, fRegister))) return 1;

#ifdef HAVE_DAEMON
    if (!fDebug) daemon(0, 0);
#endif
    
    if (!fDebug) openlog("aefsnfsd", LOG_DAEMON, 0);

    logMsg(LOG_INFO, "aefsnfsd started");

    run();

    logMsg(LOG_INFO, "aefsnfsd stopping, flushing everything...");
    commitAll();
    logMsg(LOG_INFO, "aefsnfsd stopped");

    svc_destroy(udp);
    svc_destroy(tcp);

    return 0;
}


void * nfsproc_null_2_svc(void * v, struct svc_req * rqstp)
{
    logMsg(LOG_DEBUG, "nfsproc_null");
    return VOIDOBJ;
}


attrstat * nfsproc_getattr_2_svc(nfs_fh * fh, struct svc_req * rqstp)
{
    static attrstat res;
    User user;
    fsid fs;
    CryptedFileID idFile;
        
    logMsg(LOG_DEBUG, "nfsproc_getattr");

    res.status = authCaller(rqstp, &user);
    if (res.status) return &res;

    res.status = decodeFH(fh, &fs, &idFile);
    if (res.status) return &res;

    res.status = storeAttr(&res.attrstat_u.attributes, fs, idFile);

    return &res;
}


attrstat * nfsproc_setattr_2_svc(sattrargs * args, struct svc_req * rqstp)
{
    static attrstat res;
    User user;
    fsid fs;
    CryptedFileID idFile;
    CoreResult cr;
    CryptedFileInfo info;
        
    logMsg(LOG_DEBUG, "nfsproc_setattr");

    res.status = authCaller(rqstp, &user);
    if (res.status) return &res;

    res.status = decodeFH(&args->file, &fs, &idFile);
    if (res.status) return &res;

    cr = coreQueryFileInfo(GET_VOLUME(fs), idFile, &info);
    if (cr) {
        res.status = core2nfsstat(cr);
        return &res;
    }

    smashUGID(fs, &info);

    /* Only root or the owner may change the attributes. */
    if ((user.uid != 0) && (user.uid != info.uid)) {
        res.status = NFSERR_PERM;
        return &res;
    }

    if (args->attributes.mode != -1) 
        info.flFlags = (info.flFlags & ~0777) |
            (args->attributes.mode & 0777);

    if (args->attributes.uid != -1) {
        /* Only root may change the owner. */
        if (user.uid != 0) {
            res.status = NFSERR_PERM;
            return &res;
        }
        info.uid = args->attributes.uid;
    }
    
    if (args->attributes.gid != -1)
        if (isInGroup(&user, args->attributes.gid)) {
            res.status = NFSERR_PERM;
            return &res;
        } else
            info.gid = args->attributes.gid;
    
    if (args->attributes.atime.seconds != -1)
        info.timeAccess = args->attributes.atime.seconds;
    
    if (args->attributes.mtime.seconds != -1)
        info.timeWrite = args->attributes.mtime.seconds;

    cr = coreSetFileInfo(GET_VOLUME(fs), idFile, &info);
    if (cr) {
        res.status = core2nfsstat(cr);
        return &res;
    }
    
    if (args->attributes.size != -1) {
        cr = coreSetFileSize(GET_VOLUME(fs), idFile,
            args->attributes.size);
        if (cr) {
            res.status = core2nfsstat(cr);
            return &res;
        }
    }
    
    res.status = volumeDirty(fs);
    if (res.status) return &res;

    res.status = storeAttr(&res.attrstat_u.attributes, fs, idFile);
   
    return &res;
}


void * nfsproc_root_2_svc(void * arg, struct svc_req * rqstp)
{
    logMsg(LOG_DEBUG, "nfsproc_root");
    return VOIDOBJ;
}


static bool isDot(char * p)
{
    return strcmp(p, ".") == 0 || strcmp(p, "..") == 0;
}


/* Find a file in a directory by name. */
static nfsstat lookup(fsid fs, CryptedFileID idDir, char * pszName, 
    User * pUser, CryptedFileID * pidFound)
{
    DirCacheEntry * pEntry;
    CryptedDirEntry * pCur;
    nfsstat res;
    CryptedFileInfo info;
    CoreResult cr;

    *pidFound = 0;

    cr = coreQueryFileInfo(GET_VOLUME(fs), idDir, &info);
    if (cr) return core2nfsstat(cr);
    
    smashUGID(fs, &info);

    if (!CFF_ISDIR(info.flFlags)) return NFSERR_NOTDIR;

    /* Do we have lookup permission on the directory? */
    if (!havePerm(1, pUser, &info)) return NFSERR_PERM;
        
    if (strcmp(pszName, ".") == 0) {
        *pidFound = idDir;
        return NFS_OK;
    } else if (strcmp(pszName, "..") == 0) {
        res = getParentDir(fs, idDir, pidFound);
        return res ? res : NFS_OK;
    } else {

        res = queryDirEntries(fs, idDir, &pEntry);
        if (res) return res;

        for (pCur = pEntry->pFirst; pCur; pCur = pCur->pNext)
            if (strcmp(pszName, (char *) pCur->pabName) == 0) {
                *pidFound = pCur->idFile;
                return NFS_OK;
            }
    }

    return NFSERR_NOENT;
}


diropres * nfsproc_lookup_2_svc(diropargs * args, struct svc_req * rqstp)
{
    static diropres res;
    User user;
    fsid fs;
    CryptedFileID idDir, idFound;
    
    logMsg(LOG_DEBUG, "nfsproc_lookup");

    res.status = authCaller(rqstp, &user);
    if (res.status) return &res;

    res.status = decodeFH(&args->dir, &fs, &idDir);
    if (res.status) return &res;

    res.status = lookup(fs, idDir, args->name, &user, &idFound);
    if (res.status) return &res;

    encodeFH(&res.diropres_u.diropres.file, fs, idFound);
    res.status = storeAttr(&res.diropres_u.diropres.attributes,
        fs, idFound);

    return &res;
}


readlinkres * nfsproc_readlink_2_svc(nfs_fh * fh, struct svc_req * rqstp)
{
    static readlinkres res;
    static char path[NFS_MAXPATHLEN];
    fsid fs;
    CryptedFileID idLink;
    CryptedFileInfo info;
    CryptedFilePos cbRead;
    CoreResult cr;

    logMsg(LOG_DEBUG, "nfsproc_readlink");

    res.status = decodeFH(fh, &fs, &idLink);
    if (res.status) return &res;

    cr = coreQueryFileInfo(GET_VOLUME(fs), idLink, &info);
    if (cr) {
        res.status = core2nfsstat(cr);
        return &res;
    }

    if (!CFF_ISLNK(info.flFlags)) {
        res.status = 22; /* EINVAL */
        return &res;
    }

    if (info.cbFileSize >= NFS_MAXPATHLEN) {
        res.status = NFSERR_NAMETOOLONG;
        return &res;
    }

    cr = coreReadFromFile(GET_VOLUME(fs), idLink, 0,
        info.cbFileSize, (octet *) path, &cbRead);
    if (cr) {
        res.status = core2nfsstat(cr);
        return &res;
    }
    path[info.cbFileSize] = 0;

    res.readlinkres_u.data = path;
    res.status = NFS_OK;
    return &res;
}


readres * nfsproc_read_2_svc(readargs * args, struct svc_req * rqstp)
{
    static readres res;
    static octet abBuffer[NFS_MAXDATA];
    User user;
    fsid fs;
    CryptedFileID idFile;
    CoreResult cr;
    CryptedFilePos cbRead;
        
    logMsg(LOG_DEBUG, "nfsproc_read");

    res.status = authCaller(rqstp, &user);
    if (res.status) return &res;

    res.status = decodeFH(&args->file, &fs, &idFile);
    if (res.status) return &res;

    /* Do we have read permission on this file? */
    res.status = havePerm2(4, &user, fs, idFile);
    if (res.status) return &res;

    if (args->count > NFS_MAXDATA) {
        res.status = NFSERR_NXIO; /* !!! */
        return &res;
    }
    
    cr = coreReadFromFile(GET_VOLUME(fs), idFile, args->offset,
        args->count, abBuffer, &cbRead);
    if (cr) {
        res.status = core2nfsstat(cr);
        return &res;
    }

    res.readres_u.reply.data.data_len = cbRead;
    res.readres_u.reply.data.data_val = (char *) abBuffer;

    res.status = storeAttr(&res.readres_u.reply.attributes, 
        fs, idFile);
    
    return &res;
}


void * nfsproc_writecache_2_svc(void * v, struct svc_req * rqstp)
{
    logMsg(LOG_DEBUG, "nfsproc_writecache");
    return VOIDOBJ;
}


attrstat * nfsproc_write_2_svc(writeargs * args, struct svc_req * rqstp)
{
    static attrstat res;
    User user;
    fsid fs;
    CryptedFileID idFile;
    CoreResult cr;
    CryptedFilePos cbWritten;
    
    logMsg(LOG_DEBUG, "nfsproc_write");

    res.status = authCaller(rqstp, &user);
    if (res.status) return &res;

    res.status = decodeFH(&args->file, &fs, &idFile);
    if (res.status) return &res;

    /* Do we have write permission on this file? */
    res.status = havePerm2(2, &user, fs, idFile);
    if (res.status) return &res;

    cr = coreWriteToFile(GET_VOLUME(fs), idFile, args->offset,
        args->data.data_len, (octet *) args->data.data_val, 
        &cbWritten);
    if (cr) {
        res.status = core2nfsstat(cr);
        return &res;
    }

    /* Stamp the mtime. */
    res.status = stampFile(fs, idFile);
    if (res.status) return &res;

    res.status = volumeDirty(fs);
    if (res.status) return &res;

    res.status = storeAttr(&res.attrstat_u.attributes, fs, idFile);
    
    return &res;
}


static nfsstat createFile(diropargs * where, sattr * attrs, 
    User * pUser, fsid * pfs, CryptedFileID * pidFile)
{
    CryptedFileInfo info, dirinfo;
    fsid fs;
    CryptedFileID idDir, idFile;
    CoreResult cr;
    nfsstat res;

    *pidFile = 0;

    if (isDot(where->name)) return NFSERR_EXIST;

    switch (attrs->mode & 0170000) {
        case 0100000: /* regular file */
        case 0120000: /* symlink */
        case 0040000: /* directory */
            break;
        default: /* device nodes are not supported */
            return NFSERR_ACCES;
    }

    res = decodeFH(&where->dir, &fs, &idDir);
    if (res) return res;

    cr = coreQueryFileInfo(GET_VOLUME(fs), idDir, &dirinfo);
    if (cr) return core2nfsstat(cr);

    smashUGID(fs, &dirinfo);

    /* Do we have write and search permission on the directory? */
    if (!havePerm(1 | 2, pUser, &dirinfo)) return NFSERR_PERM;

    /* !!! check setuid & setgid bits on directory */

    /* Create the file. */
    memset(&info, 0, sizeof(info));
    info.flFlags = attrs->mode & 0377777;
    info.cRefs = 1;
    info.cbFileSize = (attrs->size) == -1 ? 0 : attrs->size;
    info.timeCreation = time(0);
    if (attrs->atime.seconds == -1)
      info.timeAccess = time(0);
    else
      info.timeAccess = attrs->atime.seconds;
    if (attrs->mtime.seconds == -1)
      info.timeWrite = time(0);
    else
      info.timeWrite = attrs->mtime.seconds;
    info.idParent = CFF_ISDIR(info.flFlags) ? idDir : 0;
    info.uid = (attrs->uid == -1) ? pUser->uid : attrs->uid;
    info.gid = (attrs->gid == -1) ? pUser->gid : attrs->gid;
    cr = coreCreateBaseFile(GET_VOLUME(fs), &info, &idFile);
    if (cr) return core2nfsstat(cr);

    dirtyDir(fs, idDir);

    /* Add an entry for the newly created file to the directory. */
    cr = coreAddEntryToDir(GET_VOLUME(fs), idDir, 
        where->name, idFile, 0);
    if (cr) {
	coreDeleteFile(GET_VOLUME(fs), idFile);
	return core2nfsstat(cr);
    }

    /* Stamp the directory's mtime. */
    if (res = stampFile(fs, idDir)) return res;

    res = volumeDirty(fs);
    if (res) return res;

    *pfs = fs;
    *pidFile = idFile;
    return NFS_OK;
}


diropres * nfsproc_create_2_svc(createargs * args, struct svc_req * rqstp)
{
    static diropres res;
    User user;
    fsid fs;
    CryptedFileID idFile;

    logMsg(LOG_DEBUG, "nfsproc_create");

    res.status = authCaller(rqstp, &user);
    if (res.status) return &res;

    if (CFF_ISDIR(args->attributes.mode)) {
        res.status = NFSERR_ISDIR;
        return &res;
    }

    res.status = createFile(&args->where, &args->attributes, 
        &user, &fs, &idFile);
    if (res.status) return &res;
    
    encodeFH(&res.diropres_u.diropres.file, fs, idFile);
    storeAttr(&res.diropres_u.diropres.attributes, fs, idFile);
    return &res;
}


/* Return NFS_OK if the directory is empty, NFSERR_NOTEMPTY if it's
   not. */
static nfsstat checkDirEmpty(fsid fs, CryptedFileID idDir)
{
    CoreResult cr;
    CryptedDirEntry * pFirstEntry;
    cr = coreQueryDirEntries(GET_VOLUME(fs), idDir, &pFirstEntry);
    coreFreeDirEntries(pFirstEntry);
    if (cr) return cr;
    if (pFirstEntry) return NFSERR_NOTEMPTY;
    return NFS_OK;
}


/* Remove an entry from a directory and delete the file pointed to by
   that entry iff its reference count becomes zero. */
static nfsstat removeFile(fsid fs, CryptedFileID idDir, 
    char * pszName, int fDir, User * pUser)
{
    nfsstat res;
    CryptedFileID idFile;
    CryptedFileInfo info;
    CoreResult cr;

    if (isDot(pszName)) return NFSERR_EXIST;

    res = lookup(fs, idDir, pszName, pUser, &idFile);
    if (res) return res;

    cr = coreQueryFileInfo(GET_VOLUME(fs), idFile, &info);
    if (cr) return core2nfsstat(cr);

    smashUGID(fs, &info);

    if (fDir) {
        if (!CFF_ISDIR(info.flFlags)) return NFSERR_NOTDIR;
        res = checkDirEmpty(fs, idFile);
        if (res) return res;
    } else
        if (CFF_ISDIR(info.flFlags)) return NFSERR_ISDIR;
    
    /* Do we have write and search permission on the directory? */
    res = havePerm2(1 | 2, pUser, fs, idDir);
    if (res) return res;

    /* !!! check sticky bit */

    dirtyDir(fs, idDir);
    dirtyDir(fs, idFile);

    cr = coreMoveDirEntry(GET_VOLUME(fs), pszName, idDir, 0, 0);
    if (cr) return core2nfsstat(cr);

    /* Stamp the directory's mtime. */
    if (res = stampFile(fs, idDir)) return res;

    /* Decrease reference count and delete if appropriate. */
    info.cRefs--;
    if (fDir || (info.cRefs == 0))
        cr = coreDeleteFile(GET_VOLUME(fs), idFile);
    else
        cr = coreSetFileInfo(GET_VOLUME(fs), idFile, &info);
    if (cr) res = core2nfsstat(cr);

    res = volumeDirty(fs);
    if (res) return res;

    return NFS_OK;
}


nfsstat * nfsproc_remove_2_svc(diropargs * args, struct svc_req * rqstp)
{
    static nfsstat res;
    User user;
    fsid fs;
    CryptedFileID idDir;

    logMsg(LOG_DEBUG, "nfsproc_remove");

    res = authCaller(rqstp, &user);
    if (res) return &res;

    res = decodeFH(&args->dir, &fs, &idDir);
    if (res) return &res;

    res = removeFile(fs, idDir, args->name, false, &user);
    return &res;
}


nfsstat * nfsproc_rename_2_svc(renameargs * args, struct svc_req * rqstp)
{
    static nfsstat res;
    User user;
    CoreResult cr;
    fsid fs, fs2;
    CryptedFileID idFrom, idTo, idSrc, idDst;
    CryptedFileInfo infoSrc, infoDst;

    logMsg(LOG_DEBUG, "nfsproc_rename");

    res = authCaller(rqstp, &user);
    if (res) return &res;

    if (isDot(args->from.name) || isDot(args->to.name)) {
        res = NFSERR_EXIST;
        return &res;
    }

    res = decodeFH(&args->from.dir, &fs, &idFrom);
    if (res) return &res;
    res = decodeFH(&args->to.dir, &fs2, &idTo);
    if (res) return &res;
    if (fs != fs2) {
        res = NFSERR_STALE; /* actually, not stale but invalid */
        return &res;
    }

    /* Do we have write and search permission on both directories? */
    res = havePerm2(1 | 2, &user, fs, idFrom);
    if (res) return &res;
    res = havePerm2(1 | 2, &user, fs, idTo);
    if (res) return &res;

    /* Look up the source. */
    res = lookup(fs, idFrom, args->from.name, &user, &idSrc);
    if (res) return &res;

    cr = coreQueryFileInfo(GET_VOLUME(fs), idSrc, &infoSrc);
    if (cr) {
        res = core2nfsstat(cr);
        return &res;
    }

    /* Look up the target. */
    res = lookup(fs, idTo, args->to.name, &user, &idDst);
    if (res && res != NFSERR_NOENT) return &res;

    if (!res) {

        /* If the target already exists, it should be "compatible"
           (according to NFS version 3), i.e. the target and source
           should both be a non-directory or both be a directory.  If
           the target is a directory, it must be empty.  The target is
           deleted. */
        
        cr = coreQueryFileInfo(GET_VOLUME(fs), idDst, &infoDst);
        if (cr) {
            res = core2nfsstat(cr);
            return &res;
        }
        
        if (CFF_ISDIR(infoSrc.flFlags) != CFF_ISDIR(infoDst.flFlags)) {
            res = NFSERR_EXIST;
            return &res;
        }

        /* Remove the target.  removeFile() will check whether the
           directory is empty. */
        res = removeFile(fs, idTo, args->to.name,
            CFF_ISDIR(infoDst.flFlags), &user);
        if (res) return &res;
    }
    
    dirtyDir(fs, idFrom);
    dirtyDir(fs, idTo);

    cr = coreMoveDirEntry(GET_VOLUME(fs),
        args->from.name, idFrom,
        args->to.name, idTo);
    if (cr) {
        res = core2nfsstat(cr);
        return &res;
    }
    
    /* Stamp the mtimes of the directories. */
    if (res = stampFile(fs, idFrom)) return &res;
    if (res = stampFile(fs, idTo)) return &res;

    res = volumeDirty(fs);
    if (res) return &res;

    res = NFS_OK;
    return &res;
}


nfsstat * nfsproc_link_2_svc(linkargs * args, struct svc_req * rqstp)
{
    static nfsstat res;

    logMsg(LOG_DEBUG, "nfsproc_link");

    res = 95; /* ENOTSUP */
    return &res;
#if 0
    static nfsstat res;
    CoreResult cr;
    fsid fs, fs2;
    CryptedFileID idFile, idDir;

    res = decodeFH(&args->from, &fs, &idFile);
    if (res) return &res;
    res = decodeFH(&args->to.dir, &fs2, &idDir);
    if (res) return &res;
    if (fs != fs2) {
        res = NFSERR_STALE; /* actually, not stale but invalid */
        return &res;
    }
    
    dirtyDir(fs, idDir);

    cr = coreAddEntryToDir(GET_VOLUME(fs),
        idDir, args->to.name, idFile, 0);
    if (cr) {
        res = core2nfsstat(cr);
        return &res;
    }

    /* !!! inc ref count */

    res = volumeDirty(fs);
    if (res) return &res;
    
    res = NFS_OK;
    return &res;
#endif
}


nfsstat * nfsproc_symlink_2_svc(symlinkargs * args, struct svc_req * rqstp)
{
    static nfsstat res;
    User user;
    fsid fs;
    CryptedFileID idLink;
    CoreResult cr;
    CryptedFilePos cbWritten;

    logMsg(LOG_DEBUG, "nfsproc_symlink");

    res = authCaller(rqstp, &user);
    if (res) return &res;

    /* We ignore the attributes given by the caller.  (Perhaps we
       should check them first?) */

    args->attributes.mode = 0777 | CFF_IFLNK;
    args->attributes.uid = -1;
    args->attributes.gid = -1;
    args->attributes.size = 0;
    args->attributes.atime.seconds = -1;
    args->attributes.atime.useconds = -1;
    args->attributes.mtime.seconds = -1;
    args->attributes.mtime.useconds = -1;

    res = createFile(&args->from, &args->attributes, 
        &user, &fs, &idLink);
    if (res) return &res;

    cr = coreWriteToFile(GET_VOLUME(fs), idLink, 0,
        strlen(args->to), (octet *) args->to, &cbWritten);
    if (cr) {
        res = core2nfsstat(cr);
        return &res;
    }
    
    res = volumeDirty(fs);
    if (res) return &res;

    res = NFS_OK;
    return &res;
}


diropres * nfsproc_mkdir_2_svc(createargs * args, struct svc_req * rqstp)
{
    static diropres res;
    User user;
    fsid fs;
    CryptedFileID idNewDir;

    logMsg(LOG_DEBUG, "nfsproc_mkdir");

    res.status = authCaller(rqstp, &user);
    if (res.status) return &res;

    if (!CFF_ISDIR(args->attributes.mode)) {
        res.status = NFSERR_NOTDIR;
        return &res;
    }

    res.status = createFile(&args->where, &args->attributes, &user,
        &fs, &idNewDir);
    if (res.status) return &res;
    
    encodeFH(&res.diropres_u.diropres.file, fs, idNewDir);
    storeAttr(&res.diropres_u.diropres.attributes, fs, idNewDir);
    return &res;
}


nfsstat * nfsproc_rmdir_2_svc(diropargs * args, struct svc_req * rqstp)
{
    static nfsstat res;
    User user;
    fsid fs;
    CryptedFileID idDir;

    logMsg(LOG_DEBUG, "nfsproc_rmdir");

    res = authCaller(rqstp, &user);
    if (res) return &res;

    res = decodeFH(&args->dir, &fs, &idDir);
    if (res) return &res;

    res = removeFile(fs, idDir, args->name, true, &user);
    return &res;
}


#define MAX_ENTRIES 512
/* This has to fit in a *signed* 32-bit integer, or else many Linux
   programs will choke!  By the way, using this magic cookie means
   that you cannot have more than 2^31 files on a volume :-) */
#define EOL_COOKIE ((uint32) 0x7fffffff)

readdirres * nfsproc_readdir_2_svc(readdirargs * args, struct svc_req * rqstp)
{
    static readdirres res;
    static entry ent[MAX_ENTRIES];
    static char szName[NFS_MAXDATA];
    char * p = szName;
    User user;
    fsid fs;
    CryptedFileID idDir;
    DirCacheEntry * pEntry;
    uint32 cookie, entpos, iEntry;
    unsigned int size = 64;
    CryptedFileID idFile;

    logMsg(LOG_DEBUG, "nfsproc_readdir, count=%d", args->count);

    res.status = authCaller(rqstp, &user);
    if (res.status) return &res;

    res.status = decodeFH(&args->dir, &fs, &idDir);
    if (res.status) return &res;

    /* Do we have read permission on this directory? */
    res.status = havePerm2(4, &user, fs, idDir);
    if (res.status) return &res;

    cookie = ntohl(* (uint32 *) args->cookie);

    if (args->count > NFS_MAXDATA) args->count = NFS_MAXDATA;
    
    res.status = queryDirEntries(fs, idDir, &pEntry);
    if (res.status) return &res;

    iEntry = 0;

    for (entpos = 0;
         (entpos < MAX_ENTRIES) && (size < args->count);
         entpos++)
    {
        if (cookie == 0) {
            idFile = idDir;
            strcpy(p, ".");
            cookie = 1;
        } else if (cookie == 1) {
            res.status = getParentDir(fs, idDir, &idFile);
            if (res.status) return &res;
            if (!idFile) idFile = 1;
            strcpy(p, "..");
            cookie = pEntry->cEntries ?
                pEntry->papSortedByID[0]->idFile : EOL_COOKIE;
        } else {
            while ((iEntry < pEntry->cEntries) &&
                   (pEntry->papSortedByID[iEntry]->idFile < cookie)) 
                iEntry++;
            if (iEntry >= pEntry->cEntries) break;
            idFile = pEntry->papSortedByID[iEntry]->idFile;
            strncpy(p, (char *)
                pEntry->papSortedByID[iEntry]->pabName,
                NFS_MAXNAMLEN);
            p[NFS_MAXNAMLEN] = 0;
            iEntry++;
            cookie = (iEntry < pEntry->cEntries) ? 
                pEntry->papSortedByID[iEntry]->idFile : EOL_COOKIE;
        }

        if (entpos > 0) ent[entpos - 1].nextentry = ent + entpos;
        ent[entpos].fileid = idFile;
        ent[entpos].name = p;
        * (uint32 *) ent[entpos].cookie = htonl(cookie);
        ent[entpos].nextentry = 0;
        size += strlen(p) + 24; /* !!! should be tighter */
        p += strlen(p) + 1;
        if (cookie == 0) break;
    }

    res.readdirres_u.reply.eof = cookie == EOL_COOKIE;
    res.readdirres_u.reply.entries = entpos > 0 ? ent : 0;
    res.status = NFS_OK;
    return &res;
}


statfsres * nfsproc_statfs_2_svc(nfs_fh * fh, struct svc_req * rqstp)
{
    static statfsres res;
    logMsg(LOG_DEBUG, "nfsproc_statfs");
    res.status = NFS_OK;
    res.statfsres_u.reply.tsize = 4096;
    res.statfsres_u.reply.bsize = SECTOR_SIZE;
    res.statfsres_u.reply.tsize = 1000000;
    res.statfsres_u.reply.tsize = 500000;
    res.statfsres_u.reply.tsize = 500000;
    return &res;
}


void * mountproc_null_1_svc(void * v, struct svc_req * rqstp)
{
    logMsg(LOG_DEBUG, "mountproc_null");
    return VOIDOBJ;
}


fhstatus * mountproc_mnt_1_svc(dirpath * path, struct svc_req * rqstp)
{
    static fhstatus res;
    User user;
    char szCanon[MNTPATHLEN + 16];
    unsigned int i;
    Filesystem * pFS;

    logMsg(LOG_DEBUG, "mountproc_mnt");

    res.fhs_status = authCaller(rqstp, &user);
    if (res.fhs_status) return &res;

    canonicalizePath(*path, szCanon);
    
    for (i = 0; i < MAX_FILESYSTEMS; i++) {
        pFS = apFilesystems[i];
        if (pFS &&
            (strcmp(szCanon, GET_SUPERBLOCK(i)->pszBasePath) == 0)) {
            encodeFH((nfs_fh *) res.fhstatus_u.fhs_fhandle,
                i, GET_SUPERBLOCK(i)->idRoot);
            pFS->cRefs++;
            res.fhs_status = NFS_OK;
            return &res;
        }
    }

    res.fhs_status = NFSERR_NOENT;
    return &res;
}


mountlist * mountproc_dump_1_svc(void * v, struct svc_req * rqstp)
{
    static mountlist res = 0;
    logMsg(LOG_DEBUG, "mountproc_dump");
    return &res;
}


void * mountproc_umnt_1_svc(dirpath * path, struct svc_req * rqstp)
{
    static fhstatus res;
    User user;
    char szCanon[MNTPATHLEN + 16];
    unsigned int i;
    Filesystem * pFS;

    logMsg(LOG_DEBUG, "mountproc_umnt");

    res.fhs_status = authCaller(rqstp, &user);
    if (res.fhs_status) return &res;

    canonicalizePath(*path, szCanon);
    
    for (i = 0; i < MAX_FILESYSTEMS; i++) {
        pFS = apFilesystems[i];
        if (pFS &&
            (strcmp(szCanon, GET_SUPERBLOCK(i)->pszBasePath) == 0)) {
            pFS->cRefs--;
            /* !!! print error if cRefs < 0 */
            if (pFS->cRefs <= 0) {
                logMsg(LOG_DEBUG, "dropping volume");
                dirtyDir(i, 0);
                commitVolume(i);
                coreDropSuperBlock(GET_SUPERBLOCK(i));
                free(pFS);
                apFilesystems[i] = 0;
            }
            res.fhs_status = NFS_OK;
            return &res;
        }
    }

    res.fhs_status = NFSERR_NOENT;
    return &res;
}


void * mountproc_umntall_1_svc(void * v, struct svc_req * rqstp)
{
    logMsg(LOG_DEBUG, "mountproc_umntall");
    return VOIDOBJ;
}


exports * mountproc_export_1_svc(void * v, struct svc_req * rqstp)
{
    static exports res;
    static exportnode nodes[MAX_FILESYSTEMS];
    static groupnode group = { "localhost", 0 };
    exportnode * * prev = &res;
    unsigned int i;
    
    logMsg(LOG_DEBUG, "mountproc_export");

    for (i = 0; i < MAX_FILESYSTEMS; i++) {
        if (apFilesystems[i]) {
            *prev = &nodes[i];
            nodes[i].ex_dir = GET_SUPERBLOCK(i)->pszBasePath;
            nodes[i].ex_groups = &group;
            prev = &nodes[i].ex_next;
        }
    }
    
    *prev = 0;
    
    return &res;
}


exports * mountproc_exportall_1_svc(void * v, struct svc_req * rqstp)
{
    logMsg(LOG_DEBUG, "mountproc_exportall");
    return mountproc_export_1_svc(v, rqstp);
}


void * aefsctrlproc_null_1_svc(void * v, struct svc_req * rqstp)
{
    logMsg(LOG_DEBUG, "aefsctrlproc_null");
    return VOIDOBJ;
}


addfsres * aefsctrlproc_addfs_1_svc(addfsargs * args, struct svc_req * rqstp)
{
    static addfsres res;
    CryptedVolumeParms parms;
    char szCanon[AEFSCTRL_MAXPATHLEN + 16];
    SuperBlock * pSuperBlock;
    User user;
    CoreResult cr;
    unsigned int i;

    logMsg(LOG_DEBUG, "aefsctrlproc_addfs");

    res.cr = 0;
    
    if (authCaller(rqstp, &user)) {
        res.stat = ADDFS_PERM;
        return &res;
    }
        
    canonicalizePath(args->path, szCanon);

    /* Perhaps we already have the key? */
    for (i = 0; i < MAX_FILESYSTEMS; i++)
        if (apFilesystems[i] &&
            (strcmp(szCanon, GET_SUPERBLOCK(i)->pszBasePath) == 0)) {
            res.stat = ADDFS_HAVE_KEY;
            return &res;
        }
    
    /* No, find a free slot in apFilesystems. */
    for (i = 0; i < MAX_FILESYSTEMS; i++)
        if (!apFilesystems[i]) break;
    
    if (i >= MAX_FILESYSTEMS) {
        res.stat = ADDFS_MAX_FS;
        return &res;
    }

    coreSetDefVolumeParms(&parms);
    parms.fReadOnly = args->flags & AF_READONLY;
    parms.dirtyCallBack = dirtyCallBack;
    parms.pUserData = (void *) i; /* hack! */
#ifdef SYSTEM_posix
    parms.cred.fEnforce = true;
    parms.cred.uid = args->stor_uid;
    parms.cred.gid = args->stor_gid;
    parms.cred.mode = args->stor_mode;
#endif

    /* Read the superblock, initialize volume structures. */
retry:
    cr = coreReadSuperBlock(szCanon, args->key,
        cipherTable, &parms, &pSuperBlock);
    if (cr) {
        if (pSuperBlock) coreDropSuperBlock(pSuperBlock);
        if (!parms.fReadOnly) {
            parms.fReadOnly = true;
            goto retry;
        }
        res.stat = ADDFS_CORE;
        res.cr = cr;
        return &res;
    }

    /* Is the volume dirty? */
    if (pSuperBlock->flFlags & SBF_DIRTY) {
/*         logMsg(L_WARN, "volume %s is dirty", szCanon); */
        if (!(args->flags & AF_MOUNTDIRTY)) {
            coreDropSuperBlock(pSuperBlock);
            res.stat = ADDFS_DIRTY;
            return &res;
        }
    }

    apFilesystems[i] = malloc(sizeof(Filesystem));
    if (!apFilesystems[i]) {
        coreDropSuperBlock(pSuperBlock);
        res.stat = ADDFS_FAIL;
        return &res;
    }

    apFilesystems[i]->pSuperBlock = pSuperBlock;
    apFilesystems[i]->uid = args->fs_uid;
    apFilesystems[i]->gid = args->fs_gid;
    apFilesystems[i]->cRefs = 0;
    apFilesystems[i]->fLazyWrite = args->flags & AF_LAZYWRITE;;

    res.stat = ADDFS_OK;
    return &res;
}


void * aefsctrlproc_flush_1_svc(void * v, struct svc_req * rqstp)
{
    User user;
    logMsg(LOG_DEBUG, "nfsproc_flush");
    if (authCaller(rqstp, &user)) return VOIDOBJ;
    commitAll();
    return VOIDOBJ;
}
