/* aefsfuse.h - AEFS FUSE header file.
   Copyright (C) 2001, 2002 Eelco Dolstra (eelco@cs.uu.nl).

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

#ifndef _AEFSFUSE_H
#define _AEFSFUSE_H

#include "fuse.h"
#include "fuse_kernel.h"

#include "sysdep.h"
#include "logging.h"


bool runLoop();
void setFuseFD(int fd);
void commitVolume();

/* Syscall implementations. */
int do_lookup(struct fuse_in_header * in, char * name, 
    struct fuse_entry_out * out);
int do_setattr(struct fuse_in_header * in, struct fuse_setattr_in * arg, 
    struct fuse_attr_out * out);
int do_getattr(struct fuse_in_header * in, 
    struct fuse_attr_out * out);
int do_readlink(struct fuse_in_header * in, char * outbuf);
int do_mknod(struct fuse_in_header * in, struct fuse_mknod_in * arg, 
    char * pszName, struct fuse_entry_out * out);
int do_mkdir(struct fuse_in_header * in, struct fuse_mkdir_in * arg,
    char * pszName, struct fuse_entry_out * out);
int do_remove(struct fuse_in_header * in, char * pszName);
int do_symlink(struct fuse_in_header * in, 
    char * pszName, char * pszTarget, struct fuse_entry_out * out);
int do_rename(struct fuse_in_header * in, struct fuse_rename_in * arg,
    char * pszFrom, char * pszTo);
int do_link(struct fuse_in_header * in, struct fuse_link_in * arg,
    char * pszName, struct fuse_entry_out * out);
int do_open(struct fuse_in_header * in, struct fuse_open_in * arg);
int do_read(struct fuse_in_header * in, struct fuse_read_in * arg, 
    char * outbuf);
int do_write(struct fuse_in_header * in, struct fuse_write_in * arg,
    void * pData, struct fuse_write_out * out);
int do_statfs(struct fuse_in_header * in, struct fuse_statfs_out * out);
int do_fsync(struct fuse_in_header * in, struct fuse_fsync_in * arg);
int do_init(struct fuse_in_header * in, struct fuse_init_in_out * arg,
    struct fuse_init_in_out * out);
int do_opendir(struct fuse_in_header * in, struct fuse_open_in * arg,
    struct fuse_open_out * out);
int do_readdir(struct fuse_in_header * in, struct fuse_read_in * arg, 
    char * outbuf);
int do_releasedir(struct fuse_in_header * in, struct fuse_release_in * arg);


#endif /* !_AEFSFUSE_H */
