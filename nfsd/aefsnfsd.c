#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <rpc/rpc.h>

#include "sysdep.h"
#include "ciphertable.h"
#include "corefs.h"
#include "coreutils.h"
#include "superblock.h"

#include "nfs_prot.h"
#include "mount.h"


#define NOTIMPL assert(0); return 0;



void nfs_program_2(struct svc_req * rqstp, SVCXPRT * transp);
void mountprog_1(struct svc_req * rqstp, SVCXPRT * transp);
void nlm_prog_1(struct svc_req * rqstp, SVCXPRT * transp);


groupnode groupNode1;
groupnode groupNode2;
exportnode exportNode1;
exports exportList;

SuperBlock * pSuperBlock;

char * pszProgramName;

int voidthing;
#define VOIDOBJ ((void *) &voidthing)


void encodeFH(nfs_fh * fh, CryptedFileID id)
{
    * ((CryptedFileID *) fh->data) = id;
}


void decodeFH(nfs_fh * fh, CryptedFileID * pid)
{
    *pid = * ((CryptedFileID *) fh->data);
}


nfsstat core2nfsstat(CoreResult cr)
{
    switch (cr) {
        case CORERC_OK: return NFS_OK;
        case CORERC_FILE_NOT_FOUND: return NFSERR_NOENT;
        case CORERC_NOT_ENOUGH_MEMORY: return 12; /* ENOMEM */
        case CORERC_FILE_EXISTS: return NFSERR_EXIST;
        case CORERC_INVALID_PARAMETER: abort();
        case CORERC_INVALID_NAME: return 22; /* EINVAL */
        case CORERC_BAD_CHECKSUM: return NFSERR_IO;
        case CORERC_STORAGE: return NFSERR_IO;
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
            fprintf(stderr, "unexpected corefs error %d\n", cr);
            return NFSERR_PERM;
    }
}


nfsstat storeAttr(fattr * pAttr, CryptedFileID idFile)
{
    CoreResult cr;
    CryptedFileInfo info;
    
    cr = coreQueryFileInfo(pSuperBlock->pVolume, idFile, &info);
    if (cr) return core2nfsstat(cr);

    switch (info.flFlags & CFF_IFMT) {
        case CFF_IFREG: pAttr->type = NFREG; break;
        case CFF_IFDIR: pAttr->type = NFDIR; break;
        case CFF_IFBLK: pAttr->type = NFBLK; break;
        case CFF_IFCHR: pAttr->type = NFCHR; break;
        case CFF_IFLNK: pAttr->type = NFLNK; break;
        default: pAttr->type = NFNON;
    }

    pAttr->mode = info.flFlags;
    pAttr->nlink = info.cRefs;
    pAttr->uid = 500;
    pAttr->gid = 100;
    pAttr->size = info.cbFileSize;
    pAttr->blocksize = SECTOR_SIZE;
    pAttr->rdev = 0;
    pAttr->blocks = info.csAllocated;
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


nfsstat getParentDir(CryptedFileID idDir, CryptedFileID * pidParent)
{
    CoreResult cr;
    CryptedFileInfo info;

    *pidParent = 0;
    
    cr = coreQueryFileInfo(pSuperBlock->pVolume, idDir, &info);
    if (cr) return core2nfsstat(cr);

    *pidParent = info.idParent;
    
    return NFS_OK;
}


typedef struct {
        CryptedFileID idDir;
        int cEntries;
        CryptedDirEntry * pFirst;
        CryptedDirEntry * * papSortedByID;
} DirCacheEntry;


void freeDirCacheEntry(DirCacheEntry * pEntry)
{
    if (pEntry->pFirst) coreFreeDirEntries(pEntry->pFirst);
    if (pEntry->papSortedByID) free(pEntry->papSortedByID);
    free(pEntry);
}


#define DIRCACHE_SIZE 1
static DirCacheEntry * dirCache[DIRCACHE_SIZE];


int compareIDs(const void * p1, const void * p2)
{
    return
        (* * (CryptedDirEntry * *) p1).idFile -
        (* * (CryptedDirEntry * *) p2).idFile;
}


nfsstat queryDirEntries(CryptedFileID idDir,
    DirCacheEntry * * ppEntry)
{
    int i, j;
    DirCacheEntry * pEntry;
    CryptedDirEntry * pCur;
    CoreResult cr;
    
    for (i = 0; i < DIRCACHE_SIZE; i++)
        if (dirCache[i] && (dirCache[i]->idDir == idDir)) {
            /* Move pEntry to the front of the MRU list. */
            pEntry = dirCache[i];
            for (j = i + 1; j < DIRCACHE_SIZE; j++)
                dirCache[j - 1] = dirCache[j];
            for (j = DIRCACHE_SIZE - 1; j > 0; j++)
                dirCache[j] = dirCache[j - 1];
            dirCache[0] = pEntry;
            *ppEntry = pEntry;
            return NFS_OK;
        }

    pEntry = malloc(sizeof(DirCacheEntry)); /* !!! */
    if (!pEntry) return 12; /* ENOMEM */

    pEntry->idDir = idDir;
    pEntry->pFirst = 0;
    pEntry->papSortedByID = 0;

    cr = coreQueryDirEntries(pSuperBlock->pVolume, idDir,
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
    for (j = DIRCACHE_SIZE - 1; j > 0; j++)
        dirCache[j] = dirCache[j - 1];

    dirCache[0] = pEntry;

    *ppEntry = pEntry;
    return NFS_OK;
}


/* Remove the cached directory contents. */
void dirtyDir(CryptedFileID idDir)
{
    int i, j;
    for (i = 0; i < DIRCACHE_SIZE; i++)
        if (dirCache[i] && (dirCache[i]->idDir == idDir)) {
            freeDirCacheEntry(dirCache[i]);
            for (j = i + 1; j < DIRCACHE_SIZE; j++)
                dirCache[j - 1] = dirCache[j];
	    dirCache[DIRCACHE_SIZE - 1] = 0;
	}
}


nfsstat stampDir(CryptedFileID idDir)
{
    CoreResult cr;
    CryptedFileInfo info;

    /* Update the directory's last-written (mtime) timestamp. */
    cr = coreQueryFileInfo(pSuperBlock->pVolume, idDir, &info);
    if (cr) return core2nfsstat(cr);
    
    info.timeWrite = time(0);
    
    cr = coreSetFileInfo(pSuperBlock->pVolume, idDir, &info);
    if (cr) return core2nfsstat(cr);

    return NFS_OK;
}


int makeSocket(int protocol)
{
    int s, res;
    struct sockaddr_in addr;
    
    s = socket(
        PF_INET,
        protocol == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM,
        protocol);
    if (s == -1) return -1;
        
    addr.sin_family = AF_INET;
    addr.sin_port = htons(2050);
    addr.sin_addr.s_addr = INADDR_ANY;
    memset(addr.sin_zero, 0, sizeof(addr.sin_zero));
    res = bind(s, (struct sockaddr *) &addr, sizeof(addr));
    if (res == -1) return -1;

    return s;
}


int createAndRegister(int protocol)
{
    SVCXPRT * transp;
    int s;
    
    s = makeSocket(protocol);
    if (s == -1) {
        fprintf(stderr, "%s: cannot bind to port %d: %s",
            pszProgramName, 2050, strerror(errno));
        return -1;
    }

    if (protocol == IPPROTO_UDP) 
        transp = svcudp_create(s);
    else
        transp = svctcp_create(s, 0, 0);
    if (transp == NULL) {
        fprintf(stderr, "%s: cannot create service\n", pszProgramName);
        return -1;
    }

    if (!svc_register(transp, NFS_PROGRAM, NFS_VERSION, nfs_program_2, 0) ||
        !svc_register(transp, MOUNTPROG, MOUNTVERS, mountprog_1, 0) /* ||
        !svc_register(transp, NLM_PROG, NLM_VERS, nlm_prog_1, protocol) */)
    {
        fprintf(stderr,
            "%s: unable to register service with portmapper\n",
            pszProgramName);
        return -1;
    }

    return 0;
}



int main(int argc, char * * argv)
{
    CoreResult cr;
    CryptedVolumeParms vparms;
    int i;
    
    pszProgramName = argv[0];
   
    sysInitPRNG();

    coreSetDefVolumeParms(&vparms);
    vparms.fReadOnly = FALSE;

    cr = coreReadSuperBlock("/home/eelco/Dev/aefs/nfsd/test/", "",
        cipherTable, &vparms, &pSuperBlock);
    assert(!cr);

    groupNode1.gr_name = "localhost";
    groupNode1.gr_next = &groupNode2;
    groupNode2.gr_name = "hagbard";
    groupNode2.gr_next = 0;
    exportNode1.ex_dir = "/";
    exportNode1.ex_groups = &groupNode1;
    exportNode1.ex_next = 0;
    exportList = &exportNode1;

    for (i = 0; i < DIRCACHE_SIZE; i++)
        dirCache[i] = 0;

    (void) pmap_unset(NFS_PROGRAM, NFS_VERSION);
    (void) pmap_unset(MOUNTPROG, MOUNTVERS);
/*     (void) pmap_unset(NLM_PROG, NLM_VERS); */

    if (createAndRegister(IPPROTO_UDP) == -1) return -1;
    if (createAndRegister(IPPROTO_TCP) == -1) return -1;
    
    svc_run();
    fprintf(stderr, "svc_run returned\n");
    
    return 1;
}


void * nfsproc_null_2_svc(void * v, struct svc_req * rqstp)
{
    return VOIDOBJ;
}


attrstat * nfsproc_getattr_2_svc(nfs_fh * fh, struct svc_req * rqstp)
{
    static attrstat res;
    CryptedFileID idFile;
        
    decodeFH(fh, &idFile);

    printf("getting attributes of file %ld\n", idFile);
    
    res.status = storeAttr(&res.attrstat_u.attributes, idFile);

    return &res;
}


attrstat * nfsproc_setattr_2_svc(sattrargs * args, struct svc_req * rqstp)
{
    static attrstat res;
    CryptedFileID idFile;
    CoreResult cr;
    CryptedFileInfo info;
        
    decodeFH(&args->file, &idFile);

    printf("setting attributes of file %ld\n", idFile);

    cr = coreQueryFileInfo(pSuperBlock->pVolume, idFile, &info);
    if (cr) {
        res.status = core2nfsstat(cr);
        return &res;
    }

    if (args->attributes.mode != -1) 
        info.flFlags = (info.flFlags & ~0777) |
            (args->attributes.mode & 0777);

    if (args->attributes.uid != -1)
        ;
    
    if (args->attributes.gid != -1)
        ;
    
    if (args->attributes.atime.seconds != -1)
        info.timeAccess = args->attributes.atime.seconds;
    
    if (args->attributes.mtime.seconds != -1)
        info.timeWrite = args->attributes.mtime.seconds;

    cr = coreSetFileInfo(pSuperBlock->pVolume, idFile, &info);
    if (cr) {
        res.status = core2nfsstat(cr);
        return &res;
    }
    
    if (args->attributes.size != -1) {
        cr = coreSetFileSize(pSuperBlock->pVolume, idFile,
            args->attributes.size);
        if (cr) {
            res.status = core2nfsstat(cr);
            return &res;
        }
    }
    
    coreFlushVolume(pSuperBlock->pVolume); /* check??? */

    res.status = storeAttr(&res.attrstat_u.attributes, idFile);
   
    return &res;
}


void * nfsproc_root_2_svc(void * arg, struct svc_req * rqstp)
{
    printf("root is obsolete\n");
    return VOIDOBJ;
}


nfsstat lookup(CryptedFileID idDir, char * pszName, 
    CryptedFileID * pidFound)
{
    DirCacheEntry * pEntry;
    CryptedDirEntry * pCur;
    nfsstat res;

    *pidFound = 0;
        
    if (strcmp(pszName, ".") == 0) {
        *pidFound = idDir;
        return NFS_OK;
    } else if (strcmp(pszName, "..") == 0) {
        res = getParentDir(idDir, pidFound);
        return res ? res : NFS_OK;
    } else {

        res = queryDirEntries(idDir, &pEntry);
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
    CryptedFileID idDir, idFound;
    
    decodeFH(&args->dir, &idDir);

    printf("lookup file %s in dir %ld\n", args->name, idDir);

    res.status = lookup(idDir, args->name, &idFound);
    if (res.status) return &res;

    encodeFH(&res.diropres_u.diropres.file, idFound);
    res.status = storeAttr(&res.diropres_u.diropres.attributes,
        idFound);

    return &res;
}


readlinkres * nfsproc_readlink_2_svc(nfs_fh * fh, struct svc_req * rqstp)
{
    static readlinkres res;
    static char path[MAXPATHLEN];
    CryptedFileID idLink;
    CryptedFileInfo info;
    CryptedFilePos cbRead;
    CoreResult cr;

    decodeFH(fh, &idLink);

    printf("read link %ld\n", idLink);

    cr = coreQueryFileInfo(pSuperBlock->pVolume, idLink, &info);
    if (cr) {
        res.status = core2nfsstat(cr);
        return &res;
    }

    if (!CFF_ISLNK(info.flFlags)) {
        res.status = 22; /* EINVAL */
        return &res;
    }

    if (info.cbFileSize >= MAXPATHLEN) {
        res.status = NFSERR_NAMETOOLONG;
        return &res;
    }

    cr = coreReadFromFile(pSuperBlock->pVolume, idLink, 0,
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
    CryptedFileID idFile;
    CoreResult cr;
    CryptedFilePos cbRead;
    
    decodeFH(&args->file, &idFile);

    printf("read %d bytes at offset %d of file %ld\n", args->count,
        args->offset, idFile);

    if (args->count > NFS_MAXDATA) {
        res.status = NFSERR_NXIO; /* !!! */
        return &res;
    }
    
    cr = coreReadFromFile(pSuperBlock->pVolume, idFile, args->offset,
        args->count, abBuffer, &cbRead);
    if (cr) {
        res.status = core2nfsstat(cr);
        return &res;
    }

    res.readres_u.reply.data.data_len = cbRead;
    res.readres_u.reply.data.data_val = (char *) abBuffer;

    res.status = storeAttr(&res.readres_u.reply.attributes, idFile);
    
    return &res;
}


void * nfsproc_writecache_2_svc(void * v, struct svc_req * rqstp)
{
    printf("writecache not implemented\n");
    return VOIDOBJ;
}


attrstat * nfsproc_write_2_svc(writeargs * args, struct svc_req * rqstp)
{
    static attrstat res;
    CryptedFileID idFile;
    CoreResult cr;
    CryptedFilePos cbWritten;
    
    decodeFH(&args->file, &idFile);

    printf("write %d bytes at offset %d of file %ld\n",
        args->data.data_len, args->offset, idFile);

    cr = coreWriteToFile(pSuperBlock->pVolume, idFile, args->offset,
        args->data.data_len, (octet *) args->data.data_val,
        &cbWritten);
    if (cr) {
        res.status = core2nfsstat(cr);
        return &res;
    }

    /* !!! stamp mtime */

    coreFlushVolume(pSuperBlock->pVolume); /* check??? */

    res.status = storeAttr(&res.attrstat_u.attributes, idFile);
    
    return &res;
}


nfsstat createFile(diropargs * where, sattr * attrs, 
    CryptedFileID * pidFile)
{
    CryptedFileInfo info;
    CryptedFileID idDir, idFile;
    CoreResult cr;

    *pidFile = 0;

    decodeFH(&where->dir, &idDir);

    printf("creating file %s in %ld\n", where->name, idDir);

    memset(&info, 0, sizeof(info));
    info.flFlags = attrs->mode & 0377777;
    info.cRefs = 1;
    info.cbFileSize = 0;
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
    cr = coreCreateBaseFile(pSuperBlock->pVolume, &info, &idFile);
    if (cr) return core2nfsstat(cr);

    cr = coreAddEntryToDir(pSuperBlock->pVolume, idDir, 
        where->name, idFile, 0);
    if (cr) {
	coreDeleteFile(pSuperBlock->pVolume, idFile);
	return core2nfsstat(cr);
    }

    dirtyDir(idDir);
    coreFlushVolume(pSuperBlock->pVolume); /* check??? */

    *pidFile = idFile;
    return NFS_OK;
}


diropres * nfsproc_create_2_svc(createargs * args, struct svc_req * rqstp)
{
    static diropres res;
    CryptedFileID idFile;

    if (CFF_ISDIR(args->attributes.mode)) {
        res.status = NFSERR_ISDIR;
        return &res;
    }

    res.status = createFile(&args->where, &args->attributes, &idFile);
    if (res.status) return &res;
    
    encodeFH(&res.diropres_u.diropres.file, idFile);
    storeAttr(&res.diropres_u.diropres.attributes, idFile);
    return &res;
}


nfsstat removeFile(CryptedFileID idDir, char * pszName, int fDir)
{
    nfsstat res;
    CryptedDirEntry * pFirstEntry;
    CryptedFileID idFile;
    CryptedFileInfo info;
    CoreResult cr;

    res = lookup(idDir, pszName, &idFile);
    if (res) return res;

    cr = coreQueryFileInfo(pSuperBlock->pVolume, idFile, &info);
    if (cr) return core2nfsstat(cr);

    if (fDir) {

        if (!CFF_ISDIR(info.flFlags)) return NFSERR_NOTDIR;

        cr = coreQueryDirEntries(pSuperBlock->pVolume, 
            idFile, &pFirstEntry);
        if (cr || pFirstEntry) {
            coreFreeDirEntries(pFirstEntry);
            return cr ? core2nfsstat(cr) : NFSERR_NOTEMPTY;
        }
        
    } else
        if (CFF_ISDIR(info.flFlags)) return NFSERR_ISDIR;
    
    cr = coreMoveDirEntry(pSuperBlock->pVolume, 
        pszName, idDir, 0, 0, 0);
    if (cr) return core2nfsstat(cr);

    info.cRefs--;
    if (fDir || (info.cRefs == 0))
        cr = coreDeleteFile(pSuperBlock->pVolume, idFile);
    else
        cr = coreSetFileInfo(pSuperBlock->pVolume, idFile, &info);
    if (cr) res = core2nfsstat(cr);

    dirtyDir(idDir);
    coreFlushVolume(pSuperBlock->pVolume); /* check??? */

    return NFS_OK;
}


nfsstat * nfsproc_remove_2_svc(diropargs * args, struct svc_req * rqstp)
{
    static nfsstat res;
    CryptedFileID idDir;

    decodeFH(&args->dir, &idDir);

    printf("remove file %s from dir %ld\n", args->name, idDir);

    res = removeFile(idDir, args->name, FALSE);
    return &res;
}


nfsstat * nfsproc_rename_2_svc(renameargs * args, struct svc_req * rqstp)
{
    static nfsstat res;
    CoreResult cr;
    CryptedFileID idFrom, idTo;

    decodeFH(&args->from.dir, &idFrom);
    decodeFH(&args->to.dir, &idTo);

    cr = coreMoveDirEntry(pSuperBlock->pVolume,
        args->from.name, idFrom,
        args->to.name, idTo,
        0);
    if (cr) {
        res = core2nfsstat(cr);
        return &res;
    }
    
    dirtyDir(idFrom);
    dirtyDir(idTo);
    coreFlushVolume(pSuperBlock->pVolume); /* check??? */

    res = NFS_OK;
    return &res;
}


nfsstat * nfsproc_link_2_svc(linkargs * args, struct svc_req * rqstp)
{
    static nfsstat res;
    CoreResult cr;
    CryptedFileID idFile, idDir;

    decodeFH(&args->from, &idFile);
    decodeFH(&args->to.dir, &idDir);
    
    cr = coreAddEntryToDir(pSuperBlock->pVolume,
        idDir, args->to.name, idFile, 0);
    if (cr) {
        res = core2nfsstat(cr);
        return &res;
    }

    dirtyDir(idDir);
    coreFlushVolume(pSuperBlock->pVolume); /* check??? */
    
    res = NFS_OK;
    return &res;
}


nfsstat * nfsproc_symlink_2_svc(symlinkargs * args, struct svc_req * rqstp)
{
    static nfsstat res;
    res = 95; /* ENOTSUP */
    return &res;
#if 0
    static nfsstat res;
    CryptedFileID idLink;
    CoreResult cr;
    CryptedFilePos cbWritten;

    if (!CFF_ISLNK(args->attributes.mode)) {
        res = 22; /* EINVAL */
        return &res;
    }

    args->attributes.mode &= ~07000;
    args->attributes.mode |= 0777;

    res = createFile(&args->from, &args->attributes, &idLink);
    if (res) return &res;

    /* !!! inc ref count */

    cr = coreWriteToFile(pSuperBlock->pVolume, idLink, 0,
        strlen(args->to), (octet *) args->to, &cbWritten);
    if (cr) {
        res = core2nfsstat(cr);
        return &res;
    }
    
    coreFlushVolume(pSuperBlock->pVolume); /* check??? */

    res = NFS_OK;
    return &res;
#endif
}


diropres * nfsproc_mkdir_2_svc(createargs * args, struct svc_req * rqstp)
{
    static diropres res;
    CryptedFileID idNewDir;

    if (!CFF_ISDIR(args->attributes.mode)) {
        res.status = NFSERR_NOTDIR;
        return &res;
    }

    res.status = createFile(&args->where, &args->attributes, &idNewDir);
    if (res.status) return &res;
    
    encodeFH(&res.diropres_u.diropres.file, idNewDir);
    storeAttr(&res.diropres_u.diropres.attributes, idNewDir);
    return &res;
}


nfsstat * nfsproc_rmdir_2_svc(diropargs * args, struct svc_req * rqstp)
{
    static nfsstat res;
    CryptedFileID idDir;

    decodeFH(&args->dir, &idDir);

    printf("remove dir %s from dir %ld\n", args->name, idDir);

    res = removeFile(idDir, args->name, TRUE);
    return &res;
}


#define MAX_ENTRIES 512

readdirres * nfsproc_readdir_2_svc(readdirargs * args, struct svc_req * rqstp)
{
    static readdirres res;
    static entry ent[MAX_ENTRIES];
    static char szName[NFS_MAXDATA];
    char * p = szName;
    CryptedFileID idDir;
    DirCacheEntry * pEntry;
    uint32 cookie, entpos, iEntry;
    int size = 64;
    CryptedFileID idFile;

    decodeFH(&args->dir, &idDir);
    cookie = ntohl(* (uint32 *) args->cookie);

    printf("reading directory %ld, cookie %d\n", idDir, cookie);

    if (args->count > NFS_MAXDATA) args->count = NFS_MAXDATA;
    
    res.status = queryDirEntries(idDir, &pEntry);
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
            res.status = getParentDir(idDir, &idFile);
            if (res.status) return &res;
            if (!idFile) idFile = 1;
            strcpy(p, "..");
            cookie = pEntry->cEntries ?
                pEntry->papSortedByID[0]->idFile : 0;
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
                pEntry->papSortedByID[iEntry]->idFile : 0;
        }

        if (entpos > 0) ent[entpos - 1].nextentry = ent + entpos;
        printf("%s, %d\n", p, cookie);
        ent[entpos].fileid = idFile;
        ent[entpos].name = p;
        * (uint32 *) ent[entpos].cookie = htonl(cookie);
        ent[entpos].nextentry = 0;
        size += strlen(p) + 24; /* !!! should be tighter */
        p += strlen(p) + 1;
        if (cookie == 0) break;
    }

    res.readdirres_u.reply.eof = cookie == 0;
    printf("%d\n", res.readdirres_u.reply.eof);
    res.readdirres_u.reply.entries = entpos > 0 ? ent : 0;
    res.status = NFS_OK;
    return &res;
}


statfsres * nfsproc_statfs_2_svc(nfs_fh * fh, struct svc_req * rqstp)
{
    static statfsres res;
    printf("returning fs status\n");
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
    return VOIDOBJ;
}


fhstatus * mountproc_mnt_1_svc(dirpath * path, struct svc_req * rqstp)
{
    static fhstatus res;
    printf("mounting %s\n", *path);
    if (strcmp(*path, "/") != 0) {
        res.fhs_status = NFSERR_NOENT;
    } else {
        res.fhs_status = NFS_OK;
        encodeFH((nfs_fh *) res.fhstatus_u.fhs_fhandle,
            pSuperBlock->idRoot);
    }
    return &res;
}


mountlist * mountproc_dump_1_svc(void * v, struct svc_req * rqstp)
{
    NOTIMPL;
}


void * mountproc_umnt_1_svc(dirpath * path, struct svc_req * rqstp)
{
    printf("umounting %s\n", *path);
    return VOIDOBJ;
}


void * mountproc_umntall_1_svc(void * v, struct svc_req * rqstp)
{
    printf("umounting all\n");
    return VOIDOBJ;
}


exports * mountproc_export_1_svc(void * v, struct svc_req * rqstp)
{
    return &exportList;
}


exports * mountproc_exportall_1_svc(void * v, struct svc_req * rqstp)
{
    return &exportList;
}


/* nlm_testres * nlm_test_1(nlm_testargs * args, struct svc_req * rqstp) */
/* { */
/*     NOTIMPL; */
/* } */
