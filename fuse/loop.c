#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "sysdep.h"

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
        fprintf(stderr, "positive error code: %i\n",  error);
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
        printf("   unique: %i, error: %i (%s), outsize: %i\n", out->unique,
            out->error, strerror(-out->error), outsize);
        fflush(stdout);
    }
                
    res = write(fdFuse, outbuf, outsize);
    if(res == -1) {
        /* ENOENT means the operation was interrupted */
        if(errno != ENOENT)
            perror("writing fuse device");
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
        printf("unique: %i, opcode: %i, ino: %li, insize: %i\n", in->unique,
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

#if 0
    case FUSE_READLINK:
        do_readlink(f, in);
        break;
#endif

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

#if 0
    case FUSE_SYMLINK:
        do_symlink(f, in, (char *) inarg, 
                   ((char *) inarg) + strlen((char *) inarg) + 1);
        break;
#endif

    case FUSE_RENAME:
        res = do_rename(in, (struct fuse_rename_in *) inarg);
        sendReply(in, res, 0, 0);
        break;

#if 0
    case FUSE_LINK:
        do_link(f, in, (struct fuse_link_in *) inarg);
        break;
#endif

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
        fprintf(stderr, "Operation %i not implemented\n", in->opcode);
        /* No need to send reply to async requests */
        if (in->unique != 0)
            sendReply(in, -ENOSYS, NULL, 0);
    }
}


bool readCommand()
{
    buflen = read(fdFuse, buf, sizeof(buf));
    if (buflen == -1) {
        perror("reading fuse device");
        return false;
    }
    if ((size_t) buflen < sizeof(struct fuse_in_header)) {
        fprintf(stderr, "short read on fuse device\n");
        return false;
    }
    return true;
}


void runLoop()
{
    while (1) {
        if (!readCommand()) {
            fprintf(stderr, "did not receive a command\n");
            break;
        }
        processCommand();
    }
}
