/* mntaefsfuse.c -- AEFS FUSE mount program.
   Copyright (C) 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: mntaefsfuse.c,v 1.1 2001/12/26 21:49:58 eelco Exp $

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
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "getopt.h"

#include "cipher.h"
#include "utilutils.h"
#include "aefsck.h"
#include "logging.h"

#include "aefsfuseint.h"


char * pszProgramName;


static void printUsage(int status)
{
   if (status)
      fprintf(stderr,
         "\nTry `%s --help' for more information.\n",
         pszProgramName);
   else {
      printf("\
Usage: %s [OPTION]... AEFS-PATH MOUNT-POINT\n\
Mount the AEFS volume stored in AEFS-PATH onto MOUNT-POINT.\n\
\n\
  -d, --debug        don't demonize, print debug info\n\
  -f, --force        force mount of dirty volume\n\
  -k, --key=KEY      use specified passphrase, do not ask\n\
  -r, --readonly     mount read-only\n\
      --help         display this help and exit\n\
      --version      output version information and exit\n\
\n\
" STANDARD_KEY_HELP "\
",
         pszProgramName);
   }
   exit(status);
}


static int startDaemon(char * pszMountPoint, FuseMountParams * params)
{
    int fdTo[2], fdFrom[2];
    int pidChild, status;
    char szEnv[128];
    CoreResult cr;

    /* Create a pipe for talking to the child. */
    if (pipe(fdTo) == -1 || pipe(fdFrom) == -1) {
        fprintf(stderr, "%s: cannot create a pipe: %s\n", 
            pszProgramName, strerror(errno));
        return 1;
    }
    sprintf(szEnv, "AEFS_FD=%d %d", fdTo[0], fdFrom[1]);
    putenv(szEnv);

    /* Fork off the daemon. */
    pidChild = fork();
    if (pidChild == -1) {
        fprintf(stderr, "%s: cannot fork: %s\n", 
            pszProgramName, strerror(errno));
        return 1;
    }

    /* Child goes here. */
    if (pidChild == 0) {
        execlp("fusermount", "fusermount", pszMountPoint, "aefsfuse", 0);
        fprintf(stderr, "%s: cannot execute fusermount: %s\n",
            pszProgramName, strerror(errno));
        _exit(1);
    }

    /* Parent goes here. */
    close(fdTo[0]);
    close(fdFrom[1]);

    /* Write the parameters to the child. */
    if (write(fdTo[1], params, sizeof(*params)) != sizeof(*params)) {
        fprintf(stderr, "%s: cannot write parameters: %s\n",
            pszProgramName, strerror(errno));
        return 1;
    }

    /* Read the result. */
    if (read(fdFrom[0], &cr, sizeof(cr)) != sizeof(cr)) {
        fprintf(stderr, "%s: cannot read daemon result: %s\n",
            pszProgramName, strerror(errno));
        return 1;
    }

    /* Wait for the child to finish. */
    while (wait(&status) != pidChild) ;

    if (cr) {
        fprintf(stderr, "%s: %s\n", pszProgramName, core2str(cr));
        return 1;
    }

    return 0;
}


int main(int argc, char * * argv)
{
    bool fForceMount = false;
    bool fReadOnly = false;
    char szPassPhrase[1024], * pszOrigKey = 0;
    int c, res;
    char * pszPassPhrase = 0, * pszBasePath, * pszMountPoint;
    FuseMountParams params;

    struct option const options[] = {
        { "help", no_argument, 0, 1 },
        { "version", no_argument, 0, 2 },
        { "debug", no_argument, 0, 'd' },
        { "key", required_argument, 0, 'k' },
        { "force", no_argument, 0, 'f' },
        { "readonly", no_argument, 0, 'r' },
        { 0, 0, 0, 0 } 
    };      

    /* Parse the arguments. */

    pszProgramName = argv[0];

    while ((c = getopt_long(argc, argv, "dfk:r", options, 0)) != EOF) {
        switch (c) {
            case 0:
                break;

            case 1: /* --help */
                printUsage(0);
                break;

            case 2: /* --version */
                printf("mntaefs - %s\n", AEFS_VERSION);
                exit(0);
                break;

            case 'd': /* --debug */
                fDebug = true;
                break;

            case 'k': /* --key */
                pszPassPhrase = pszOrigKey = optarg;
                break;

            case 'f': /* --force */
                fForceMount = true;
                break;

            case 'r': /* --readonly */
                fReadOnly = true;
                break;

            default:
                printUsage(1);
        }
    }

    if (optind != argc - 2) {
        fprintf(stderr, "%s: missing or too many parameters\n", pszProgramName);
        printUsage(1);
    }

    pszBasePath = argv[optind++];
    pszMountPoint = argv[optind++];

    memset(&params, 0, sizeof(params));
    params.fMountDirty = fForceMount;
    params.fReadOnly = fReadOnly;
    params.fDebug = fDebug;

    /* Expand the given base path. */
    if (!realpath(pszBasePath, params.szBasePath)) {
        fprintf(stderr, "%s: cannot expand path: %s\n", 
            pszProgramName, strerror(errno));
        return 1;
    }
    strcat(params.szBasePath, "/");

    /* Ask the user to enter the passphrase, if it wasn't specified
       with "-k". */
    if (!pszPassPhrase) {
        pszPassPhrase = szPassPhrase;
        if (readPhrase("passphrase: ", sizeof(szPassPhrase), szPassPhrase)) {
            fprintf(stderr, "%s: error reading passphrase\n", pszProgramName);
            return 1;
        }
    }

    /* Does the passphrase fit? */
    if (strlen(pszPassPhrase) >= sizeof(params.szPassPhrase)) {
        fprintf(stderr, "%s: passphrase is too long\n",
            pszProgramName);
        return 1;
    }
    strcpy(params.szPassPhrase, pszPassPhrase);
    memset(szPassPhrase, 0, sizeof(szPassPhrase)); /* burn */

    res = startDaemon(pszMountPoint, &params);

    memset(&params, 0, sizeof(params)); /* burn */

    return res;
}
