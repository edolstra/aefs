/* loop.c -- Implements communication with the FUSE kernel module.
   Copyright (C) 2001, 2003 Eelco Dolstra (eelco@cs.uu.nl).

   Some of the stuff here is take from FUSE, which is
   Copyright (C) 2001 Miklos Szeredi (mszeredi@inf.bme.hu)

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
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>

#include "sysdep.h"
#include "logging.h"

#include "aefsfuse.h"


#define PARAM(tp, inarg) (((char *) (inarg)) + sizeof(struct tp))


static int fdFuse = 0;
static char buf[FUSE_MAX_IN];
static ssize_t buflen;


static void sendReply(struct fuse_in_header * in, int error,
    void * arg, size_t argsize)
{
    int res;
    char * outbuf;
    size_t outsize;
    struct fuse_out_header *out;

    if (error > 0) {
        logMsg(LOG_ERR, "positive error code: %i", error);
        error = -ERANGE;
    }

    if (error)
        argsize = 0;

    outsize = sizeof(struct fuse_out_header) + argsize;
    outbuf = (char *) malloc(outsize);
    out = (struct fuse_out_header *) outbuf;
    out->len = outsize;
    out->unique = in->unique;
    out->error = error;
    if (argsize != 0)
        memcpy(outbuf + sizeof(struct fuse_out_header), arg, argsize);

    if (1) {
        logMsg(LOG_DEBUG, "   unique: %llu, error: %i (%s), outsize: %i", out->unique,
            out->error, strerror(-out->error), outsize);
    }
                
    res = write(fdFuse, outbuf, outsize);
    if (res == -1) {
        /* ENOENT means the operation was interrupted */
        if (errno != ENOENT)
            logMsg(LOG_ERR, "error writing fuse device: %s", strerror(errno));
    }

    free(outbuf);
}


static char outbuf[FUSE_MAX_IN]; /* !!! IN -> OUT */


void processCommand()
{
    struct fuse_in_header * in = (struct fuse_in_header *) buf;
    void * inarg = buf + sizeof(struct fuse_in_header);
    char * outbuf2;
    size_t argsize;
    int res;
    char * pszFrom, * pszTo;

    if (1) {
        logMsg(LOG_DEBUG, "unique: %llu, opcode: %i, ino: %lu, insize: %i", in->unique,
            in->opcode, in->nodeid, buflen);
        fflush(stdout);
    }

    argsize = buflen - sizeof(struct fuse_in_header);
        
    switch(in->opcode) {

    case FUSE_LOOKUP:
        res = do_lookup(in, (char *) inarg, (struct fuse_entry_out *) outbuf);
        sendReply(in, res, outbuf, sizeof(struct fuse_entry_out));
        break;

    case FUSE_FORGET:
        break;

    case FUSE_GETATTR:
        res = do_getattr(in, (struct fuse_attr_out *) outbuf);
        sendReply(in, res, outbuf, sizeof(struct fuse_attr_out));
        break;

    case FUSE_SETATTR:
        res = do_setattr(in, (struct fuse_setattr_in *) inarg, 
	    (struct fuse_attr_out *) outbuf);
        sendReply(in, res, outbuf, sizeof(struct fuse_attr_out));
        break;

    case FUSE_READLINK:
        outbuf2 = malloc(PATH_MAX + 1);
        res = do_readlink(in, outbuf2);
        sendReply(in, res, outbuf2, !res ? strlen(outbuf2) : 0);
        free(outbuf2);
        break;

    case FUSE_MKNOD:
        res = do_mknod(in, (struct fuse_mknod_in *) inarg,
            PARAM(fuse_mknod_in, inarg),
            (struct fuse_entry_out *) outbuf);
        sendReply(in, res, outbuf, sizeof(struct fuse_entry_out));
        break;

    case FUSE_MKDIR:
        res = do_mkdir(in, (struct fuse_mkdir_in *) inarg,
            PARAM(fuse_mkdir_in, inarg),
            (struct fuse_entry_out *) outbuf);
        sendReply(in, res, outbuf, sizeof(struct fuse_entry_out));
        break;

    case FUSE_UNLINK:
    case FUSE_RMDIR:
        res = do_remove(in, (char *) inarg);
        sendReply(in, res, 0, 0);
        break;

    case FUSE_SYMLINK:
        res = do_symlink(in, (char *) inarg,
            ((char *) inarg) + strlen((char *) inarg) + 1,
            (struct fuse_entry_out *) outbuf);
        sendReply(in, res, outbuf, sizeof(struct fuse_entry_out));
        break;

    case FUSE_RENAME:
        pszFrom = PARAM(fuse_rename_in, inarg);
        pszTo = strchr(pszFrom, 0) + 1;
        res = do_rename(in, (struct fuse_rename_in *) inarg,
            pszFrom, pszTo);
        sendReply(in, res, 0, 0);
        break;

    case FUSE_LINK:
        res = do_link(in, (struct fuse_link_in *) inarg,
            PARAM(fuse_link_in, inarg),
            (struct fuse_entry_out *) outbuf);
        sendReply(in, res, outbuf, sizeof(struct fuse_entry_out));
        break;

    case FUSE_OPEN:
        res = do_open(in, (struct fuse_open_in *) inarg);
        if (res == 0) {
            struct fuse_open_out out;
            memset(&out, 0, sizeof(out));
            sendReply(in, res, &out, sizeof out);
        } else
            sendReply(in, res, 0, 0);
        break;

    case FUSE_READ:
        outbuf2 = malloc(((struct fuse_read_in *) inarg)->size);
        res = do_read(in, (struct fuse_read_in *) inarg, outbuf2);
        sendReply(in, res > 0 ? 0 : res, outbuf2, res > 0 ? res : 0);
        free(outbuf2);
        break;

    case FUSE_WRITE:
        res = do_write(in, (struct fuse_write_in *) inarg,
            PARAM(fuse_write_in, inarg),
            (struct fuse_write_out *) outbuf);
        sendReply(in, res, outbuf, sizeof(struct fuse_write_out));
        break;

    case FUSE_STATFS:
        res = do_statfs(in, (struct fuse_statfs_out *) outbuf);
        sendReply(in, res, outbuf, sizeof(struct fuse_statfs_out));
        break;

    case FUSE_RELEASE:
        /* Last file handle closed for some file, which we don't care
           about. */
        sendReply(in, 0, 0, 0);
        break;

    case FUSE_FSYNC:
        res = do_fsync(in, (struct fuse_fsync_in *) inarg);
        sendReply(in, res, 0, 0);
        break;

    case FUSE_FLUSH:
        /* File handle closed, which we don't care about. */
        sendReply(in, 0, 0, 0);
        break;

    case FUSE_INIT: {
        struct fuse_init_in_out out;
        res = do_init(in, (struct fuse_init_in_out *) inarg, &out);
        sendReply(in, res, &out, sizeof(out));
        break;
    }

#if 0
    case FUSE_GETDIR:
        res = do_getdir(in, (struct fuse_getdir_out *) outbuf);
        sendReply(in, res, outbuf, sizeof(struct fuse_getdir_out));
        if (!res) close(((struct fuse_getdir_out *) outbuf)->fd);
        break;
#endif

    case FUSE_OPENDIR: {
        struct fuse_open_out out;
        memset(&out, 0, sizeof(out)); 
        res = do_opendir(in, (struct fuse_open_in *) inarg, &out);
        sendReply(in, res, &out, sizeof(out));
        break;
    }

    case FUSE_READDIR: {
        outbuf2 = malloc(((struct fuse_read_in *) inarg)->size);
        res = do_readdir(in, (struct fuse_read_in *) inarg, outbuf2);
        sendReply(in, res > 0 ? 0 : res, outbuf2, res > 0 ? res : 0);
        free(outbuf2);
        break;
    }

    case FUSE_RELEASEDIR: {
        res = do_releasedir(in, (struct fuse_release_in *) inarg);
        sendReply(in, res, 0, 0);
        break;
    }

    default:
        logMsg(LOG_ERR, "Operation %i not implemented", in->opcode);
        /* No need to send reply to async requests */
        if (in->unique != 0)
            sendReply(in, -ENOSYS, NULL, 0);
    }
}


static bool fTerminate = false;


/* Return true iff somebody unmounted us. */
bool runLoop()
{
    fd_set readfds;
    struct timeval timeout;
    int res;
    time_t maxAge = 5, timeFlush = time(0), timeCur;
    bool fUnmounted = false;

    while (!fTerminate) {

        logMsg(LOG_DEBUG, "loop");

        /* Lazy writer.  Should we flush now?  Determine the time-out
           for select(). */
        timeCur = time(0);
        if (timeCur >= timeFlush + maxAge) {
            commitVolume();
            timeFlush = timeCur;
            timeout.tv_sec = maxAge;
        } else
            timeout.tv_sec = timeFlush + maxAge - timeCur;
        timeout.tv_usec = 0;

        /* Sleep until we get some input, or until we should flush. */
	FD_ZERO(&readfds);
	FD_SET(fdFuse, &readfds);
        res = select(fdFuse + 1, &readfds, 0, 0, &timeout);
        if (res == -1 && errno != EINTR) {
            logMsg(LOG_ALERT, "error from select: %s",
		strerror(errno));
            break;
        }

	if (res > 0) {
	    buflen = read(fdFuse, buf, sizeof(buf));
	    if (buflen == -1) {
		logMsg(LOG_ERR, "error reading fuse device: %s", strerror(errno));
		fUnmounted = true;
                break;
	    }
	    if ((size_t) buflen < sizeof(struct fuse_in_header)) {
		logMsg(LOG_ERR, "short read on fuse device");
		break;
	    }
	    processCommand();
	}
    }

    return fUnmounted;
}


void setFuseFD(int fd)
{
    fdFuse = fd;
}
