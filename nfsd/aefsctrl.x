/* aefsctrl.x -- Control protocol for the AEFS NFS server.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: aefsctrl.x,v 1.5 2001/09/23 13:30:18 eelco Exp $

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

const AEFSNFSD_DEF_PORT = 843;

const AEFSCTRL_MAXPATHLEN = 250;

const AF_READONLY   = 1;
const AF_MOUNTDIRTY = 2;
const AF_LAZYWRITE  = 4;

struct addfsargs {
        string path<AEFSCTRL_MAXPATHLEN>;
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
    ADDFS_DIRTY = 5,	/* file system is dirty, run aefsck */
    ADDFS_PERM = 6      /* you don't have permission to talk */
};

struct addfsres {
        addfsstat stat;
        int cr; /* see ../corefs/corefs.h */
};

program AEFSCTRL_PROGRAM {
    version AEFSCTRL_VERSION_1 {
        void AEFSCTRLPROC_NULL(void) = 0;
        addfsres AEFSCTRLPROC_ADDFS(addfsargs) = 1;
	void AEFSCTRLPROC_FLUSH(void) = 123;
    } = 1;
} = 101438;
