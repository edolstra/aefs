/* loop.c -- Implements communication with the FUSE kernel module.
   Copyright (C) 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: loop.c,v 1.7 2001/12/31 16:17:58 eelco Exp $

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

#include "sysdep.h"
#include "logging.h"

#include "aefsfuse.h"


static int fdFuse = 0;
static char buf[FUSE_MAX_IN];
static ssize_t buflen;
static char outbuf[FUSE_MAX_IN]; /* !!! IN -> OUT */


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

    if(error)
        argsize = 0;

    outsize = sizeof(struct fuse_out_header) + argsize;
    outbuf = (char *) malloc(outsize);
    out = (struct fuse_out_header *) outbuf;
    out->unique = in->unique;
    out->error = error;
    if(argsize != 0)
        memcpy(outbuf + sizeof(struct fuse_out_header), arg, argsize);

    if (0) {
        logMsg(LOG_DEBUG, "   unique: %i, error: %i (%s), outsize: %i", out->unique,
            out->error, strerror(-out->error), outsize);
    }
                
    res = write(fdFuse, outbuf, outsize);
    if(res == -1) {
        /* ENOENT means the operation was interrupted */
        if(errno != ENOENT)
            logMsg(LOG_ERR, "error writing fuse device:", strerror(errno));
    }

    free(outbuf);
}


void processCommand()
{
    struct fuse_in_header * in = (struct fuse_in_header *) buf;
    void * inarg = buf + sizeof(struct fuse_in_header);
    char * outbuf2;
    size_t argsize;
    int res;

    if (0) {
        logMsg(LOG_DEBUG, "unique: %i, opcode: %i, ino: %li, insize: %i", in->unique,
            in->opcode, in->ino, buflen);
        fflush(stdout);
    }
    
    argsize = buflen - sizeof(struct fuse_in_header);
        
    switch(in->opcode) {

    case FUSE_LOOKUP:
        res = do_lookup(in, (char *) inarg, (struct fuse_lookup_out *) outbuf);
        sendReply(in, res, outbuf, sizeof(struct fuse_lookup_out));
        break;

    case FUSE_FORGET:
        break;

    case FUSE_GETATTR:
        res = do_getattr(in, (struct fuse_getattr_out *) outbuf);
        sendReply(in, res, outbuf, sizeof(struct fuse_getattr_out));
        break;

    case FUSE_SETATTR:
        res = do_setattr(in, (struct fuse_setattr_in *) inarg, 
	    (struct fuse_setattr_out *) outbuf);
        sendReply(in, res, outbuf, sizeof(struct fuse_setattr_out));
        break;

    case FUSE_READLINK:
        outbuf2 = malloc(PATH_MAX + 1);
        res = do_readlink(in, outbuf2);
        sendReply(in, res, outbuf2, !res ? strlen(outbuf2) : 0);
        free(outbuf2);
        break;

    case FUSE_GETDIR:
        res = do_getdir(in, (struct fuse_getdir_out *) outbuf);
        sendReply(in, res, outbuf, sizeof(struct fuse_getdir_out));
        if (!res) close(((struct fuse_getdir_out *) outbuf)->fd);
        break;

    case FUSE_MKNOD:
        res = do_mknod(in, (struct fuse_mknod_in *) inarg, 
	    (struct fuse_mknod_out *) outbuf);
        sendReply(in, res, outbuf, sizeof(struct fuse_mknod_out));
        break;

#if 0            
    case FUSE_MKDIR:
        res = do_mkdir(in, (struct fuse_mkdir_in *) inarg);
        sendReply(in, res, 0, 0);
        break;
#endif

    case FUSE_UNLINK:
    case FUSE_RMDIR:
        res = do_remove(in, (char *) inarg);
        sendReply(in, res, 0, 0);
        break;

    case FUSE_SYMLINK:
        res = do_symlink(in, (char *) inarg,
            ((char *) inarg) + strlen((char *) inarg) + 1);
        sendReply(in, res, 0, 0);
        break;

    case FUSE_RENAME:
        res = do_rename(in, (struct fuse_rename_in *) inarg);
        sendReply(in, res, 0, 0);
        break;

    case FUSE_LINK:
        res = do_link(in, (struct fuse_link_in *) inarg);
        sendReply(in, res, 0, 0);
        break;

    case FUSE_OPEN:
        res = do_open(in, (struct fuse_open_in *) inarg);
        sendReply(in, res, 0, 0);
        break;

    case FUSE_READ:
        outbuf2 = malloc(((struct fuse_read_in *) inarg)->size);
        res = do_read(in, (struct fuse_read_in *) inarg, outbuf2);
        sendReply(in, res > 0 ? 0 : res, outbuf2, res > 0 ? res : 0);
        free(outbuf2);
        break;

    case FUSE_WRITE:
        res = do_write(in, (struct fuse_write_in *) inarg);
        sendReply(in, res, 0, 0);
        break;

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


bool dupFuseFD()
{
    int fd, fd2;
    fd = dup(fdFuse);
    if (fd == -1) {
	logMsg(LOG_ERR, "cannot dup fuse fd: %s", strerror(errno));
	return false;
    }
    if (fdFuse < 3) {
	fd2 = open("/dev/null", O_RDONLY);
	if (fd == -1) {
	    logMsg(LOG_ERR, "cannot dup /dev/null: %s", strerror(errno));
	    return false;
	}
	dup2(fd2, fdFuse);
	close(fd2);
    } else
	close(fdFuse);
    fdFuse = fd;
    logMsg(LOG_DEBUG, "fuse fd moved to %d", fdFuse);
    return true;
}
