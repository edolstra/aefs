/* aefsadd.c -- Utility to add file systems to the AEFS NFS server.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: aefsadd.c,v 1.13 2001/09/23 13:30:18 eelco Exp $

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/socket.h>
#define PORTMAP /* enables backward compatibility under Solaris */
#include <rpc/rpc.h>

#include "getopt.h"

#include "corefs.h"
#include "aefsctrl.h"
#include "utilutils.h"


char * pszProgramName;


static void printUsage(int status)
{
    if (status)
        fprintf(stderr,
            "\nTry `%s --help' for more information.\n",
            pszProgramName);
    else {
        printf("\
Usage: %s [OPTION]... PATH\n\
Inform the AEFS NFS server of the encryption key to be used\n\
for the specified path.\n\
\n\
      --help              display this help and exit\n\
      --version           output version information and exit\n\
  -f, --force             force loading of dirty volume\n\
  -k, --key=KEY           use specified key, do not ask (dangerous!)\n\
      --lazy=[on|off]     turn lazy writing on (default) or off\n\
  -m, --mode=MODE         specify mode of new storage files (in octal)\n\
  -r, --readonly          load read-only\n\
  -u, --user=USER[.GROUP] set ownership of all files\n\
  -s, --stor=USER[.GROUP] user ID to use for ciphertext access\n\
\n\
If the key is not specified on the command-line, the user is asked\n\
to enter the key.\n\
\n\
The server is assumed to be running on `localhost'.  In response to\n\
this command, the server will try to load the encrypted file system\n\
in PATH with the specified key.  This will fail if the file system\n\
is dirty, unless `--force' is specified.  If this operation is\n\
successful, the file system can be mounted using `mount(8)'.\n\
\n\
Use `--stor' to specify which user identity should be used to access\n\
the ciphertext.  This allows you to add file systems of which the\n\
ciphertext is owned by regular users.  This is only really effective\n\
on systems that support the [sg]etfs[ug]id() system calls, i.e. Linux.\n\
If you do this, you should use `--user' as well; otherwise, the user\n\
who has write access to the ciphertext could e.g. construct a file\n\
that is setuid root.\n\
\n\
If the GROUP is omitted in `--user' or `--stor', the group ID of the\n\
user is extracted from the password file.\n\
\n\
The default for `--user' is `-1.-1', which means use the file\n\
ownership as stored in the file system.  The default for `--stor' is\n\
`root.root'.  The default for `--mode' is 0600.\n\
\n\
Examples:\n\
  Add the file system in `/crypted/fred', which is owned by user fred:\n\
    aefsadd --user=fred.users --stor=fred.users /crypted/fred\n\
",
            pszProgramName);
    }
    exit(status);
}


static int parseUGID(char * param, uid_t * puid, gid_t * pgid)
{
    char * p, * q, * sep;
    struct passwd * pw;
    struct group * gr;
    int d;

    p = malloc(strlen(param) + 1);
    assert(p);
    strcpy(p, param);
    
    for (sep = p; *sep && *sep != '.' && *sep != ':'; sep++) ;
    q = *sep ? sep + 1 : 0;
    *sep = 0;

    if (isdigit(*p)) {
        if (sscanf(p, "%d", &d) != 1) {
            fprintf(stderr, "%s: invalid user number: %s", 
                pszProgramName, p);
            free(p);
            return 1;
        }
        *puid = d;
        *pgid = 0;
    } else {
        pw = getpwnam(p);
        if (!pw) {
            fprintf(stderr, "%s: invalid user name: %s", 
                pszProgramName, p);
            free(p);
            return 1;
        }
        *puid = pw->pw_uid;
        *pgid = pw->pw_gid;
    }
    
    if (q) {
        if (isdigit(*q)) {
            if (sscanf(q, "%d", &d) != 1) {
                fprintf(stderr, "%s: invalid group number: %s", 
                    pszProgramName, q);
                free(p);
                return 1;
            }
            *pgid = d;
        } else {
            gr = getgrnam(q);
            if (!gr) {
                fprintf(stderr, "%s: invalid group name: %s", 
                    pszProgramName, q);
                free(p);
                return 1;
            }
            *pgid = gr->gr_gid;
        }
    }
    
    free(p);
    return 0;
}


int main(int argc, char * * argv)
{
    int c;
    bool fForceMount = false;
    bool fReadOnly = false;
    bool fLazyWrite = true;
    char szKey[1024], * pszKey = 0, * pszBasePath;
    struct sockaddr_in addr;
    struct timeval time;
    int socket;
    CLIENT * clnt;
    addfsargs args;
    addfsres * res;
    int ret = 1;
    uid_t user_uid = -1, stor_uid = 0;
    gid_t user_gid = -1, stor_gid = 0;
    int mode = 0600;

    struct option const options[] = {
        { "help", no_argument, 0, 1 },
        { "version", no_argument, 0, 2 },
        { "key", required_argument, 0, 'k' },
        { "force", no_argument, 0, 'f' },
        { "readonly", no_argument, 0, 'r' },
        { "mode", required_argument, 0, 'm' },
        { "lazy", required_argument, 0, 11 },
        { "user", required_argument, 0, 'u' },
        { "stor", required_argument, 0, 's' },
        { 0, 0, 0, 0 } 
    };      

    /* Parse the arguments. */
   
    pszProgramName = argv[0];

    while ((c = getopt_long(argc, argv, "fk:m:ru:s:", options, 0)) != EOF) {
        switch (c) {
            case 0:
                break;

            case 1: /* --help */
                printUsage(0);
                break;

            case 2: /* --version */
                printf("aefsadd - %s\n", AEFS_VERSION);
                exit(0);
                break;

            case 'k': /* --key */
                pszKey = optarg;
                break;

            case 'f': /* --force */
                fForceMount = true;
                break;

            case 'r': /* --readonly */
                fReadOnly = true;
                break;

            case 'm': /* --mode */
                if (sscanf(optarg, "%o", &mode) != 1) {
                    fprintf(stderr, "%s: invalid mode parameter %s", 
                        pszProgramName, optarg);
                    printUsage(1);
                }
                break;

            case 11: /* --lazy */
                if (strcmp(optarg, "on") == 0) 
                    fLazyWrite = true;
                else if (strcmp(optarg, "off") == 0) 
                    fLazyWrite = false;
                else {
                    fprintf(stderr, 
                        "%s: invalid argument to --lazy: %s", 
                        pszProgramName, optarg);
                    printUsage(1);
                }
                break;

            case 'u': /* --user */
                if (parseUGID(optarg, &user_uid, &user_gid))
                    printUsage(1);
                break;

            case 's': /* --stor */
                if (parseUGID(optarg, &stor_uid, &stor_gid))
                    printUsage(1);
                break;

            default:
                printUsage(1);
        }
    }

    if (optind != argc - 1) {
        fprintf(stderr, "%s: missing or too many parameters\n", pszProgramName);
        printUsage(1);
    }

    pszBasePath = argv[optind++];

    /* Ask the use to enter the key, if it wasn't specified with "-k". */
    if (!pszKey) {
        pszKey = szKey;
        if (readKey("key: ", sizeof(szKey), szKey)) {
            fprintf(stderr, "%s: error reading key\n", pszProgramName);
            return 1;
        }
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(AEFSNFSD_DEF_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

    time.tv_sec = 0;
    time.tv_usec = 500 * 1000;

    socket = RPC_ANYSOCK;
    clnt = clnttcp_create(&addr, AEFSCTRL_PROGRAM, AEFSCTRL_VERSION_1,
        &socket, 0, 0);
    if (!clnt) {
        clnt_pcreateerror("unable to connect to aefsnfsd (is it running?)");
        return 1;
    }

    clnt->cl_auth = authunix_create_default();

    args.path = pszBasePath;
    args.key = pszKey;
    args.flags = 
        (fReadOnly ? AF_READONLY : 0) |
        (fForceMount ? AF_MOUNTDIRTY : 0) |
        (fLazyWrite ? AF_LAZYWRITE : 0);
    args.stor_uid = stor_uid;
    args.stor_gid = stor_gid;
    args.stor_mode = mode;
    args.fs_uid = user_uid;
    args.fs_gid = user_gid;
    res = aefsctrlproc_addfs_1(&args, clnt);
    if (!res) {
        clnt_perror(clnt, "unable to add key to aefsnfsd");
        goto end;
    }

    switch (res->stat) {
        case ADDFS_OK:
            ret = 0;
            break;
        case ADDFS_HAVE_KEY:
            fprintf(stderr, "%s: daemon already has a key "
                "for this file system\n", pszProgramName);
            ret = 0;
            break;
        case ADDFS_CORE:
            if (res->cr == CORERC_BAD_CHECKSUM) {
                fprintf(stderr, "%s: invalid key\n", pszProgramName);
            } else {
                fprintf(stderr, "%s: aefsnfsd returned error: %s\n",
                    pszProgramName, core2str(res->cr));
            }
            break;
        case ADDFS_DIRTY:
            fprintf(stderr, "%s: file system is dirty, "
                "run `aefsck -f %s' and retry\n",
                pszProgramName, pszBasePath);
            break;
        case ADDFS_PERM:
            fprintf(stderr, "%s: you don't have permission to "
                "talk to the server\n", pszProgramName);
            break;
        default:
            fprintf(stderr, "%s: aefsnfsd returned error %d\n",
                pszProgramName, res->stat);
    }

end:
    auth_destroy(clnt->cl_auth);
    clnt_destroy(clnt);

    return ret;
}
