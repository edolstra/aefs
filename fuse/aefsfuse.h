/* aefsfuse.h - AEFS FUSE header file.
   Copyright (C) 2001, 2002 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: aefsfuse.h,v 1.3 2002/02/16 18:33:12 eelco Exp $

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

/* !!! fix this */
#include "../../fuse/include/linux/fuse.h"

#include "sysdep.h"
#include "logging.h"


bool runLoop();
bool dupFuseFD(void);
void commitVolume();

/* Syscall implementations. */
int do_lookup(struct fuse_in_header * in, char * name, 
    struct fuse_lookup_out * out);
int do_setattr(struct fuse_in_header * in, struct fuse_setattr_in * arg, 
    struct fuse_setattr_out * out);
int do_getattr(struct fuse_in_header * in, 
    struct fuse_getattr_out * out);
int do_readlink(struct fuse_in_header * in, char * outbuf);
int do_getdir(struct fuse_in_header * in, 
    struct fuse_getdir_out * out);
int do_mknod(struct fuse_in_header * in, struct fuse_mknod_in * arg, 
    struct fuse_mknod_out * out);
int do_remove(struct fuse_in_header * in, char * pszName);
int do_symlink(struct fuse_in_header * in, 
    char * pszName, char * pszTarget);
int do_rename(struct fuse_in_header * in, struct fuse_rename_in * arg);
int do_link(struct fuse_in_header * in, struct fuse_link_in * arg);
int do_open(struct fuse_in_header * in, struct fuse_open_in * arg);
int do_read(struct fuse_in_header * in, struct fuse_read_in * arg, 
    char * outbuf);
int do_write(struct fuse_in_header * in, struct fuse_write_in * arg);
int do_statfs(struct fuse_in_header * in, struct fuse_statfs_out * out);


#endif /* !_AEFSFUSE_H */
