const AEFSKEY_MAXPATHLEN = 250;

const AF_READONLY   = 1;
const AF_MOUNTDIRTY = 2;

struct addfsargs {
        string path<AEFSKEY_MAXPATHLEN>;
        string key<1024>;
	int flags; /* AF_* */
	int stor_uid;
	int stor_gid;
	int stor_mode;
	int fs_uid;
	int fs_gid;
};

enum addfsstat {
    ADDFS_OK = 0,       /* everything okay, can mount */
    ADDFS_HAVE_KEY = 1, /* the daemon already has the key */
    ADDFS_MAX_FS = 2,   /* file system limit reached */
    ADDFS_CORE = 3,     /* corefs error, consult cr */
    ADDFS_FAIL = 4,     /* misc. failure */
    ADDFS_DIRTY = 5	/* file system is dirty, run aefsck */
};

struct addfsres {
        addfsstat stat;
        int cr; /* see ../corefs/corefs.h */
};

program AEFSKEY_PROGRAM {
    version AEFSKEY_VERSION_1 {
        void AEFSKEYPROC_NULL(void) = 0;
        addfsres AEFSKEYPROC_ADDFS(addfsargs) = 1;
    } = 1;
} = 101438;
