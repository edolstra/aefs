#include <stdio.h>
#include <string.h>
#include <errno.h>

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
      --help          display this help and exit\n\
      --version       output version information and exit\n\
  -f, --force         force loading of dirty volume\n\
  -g, --gid=UID       specify the gid of the storage files\n\
  -k, --key=KEY       use specified key, do not ask (dangerous!)\n\
      --lazy=[on|off] turn lazy writing on (default) or off\n\
  -m, --mode=MODE     specify the mode of new storage files\n\
  -r, --readonly      load read-only\n\
  -u, --uid=UID       specify the uid of the storage files\n\
\n\
If the key is not specified on the command-line, the user is asked\n\
to enter the key.\n\
\n\
The server is assumed to be running on `localhost'.  In response to\n\
this command, the server will try to load the encrypted file system\n\
in PATH with the specified key.  This will fail if the file system\n\
is dirty, unless `--force' is specified.  If this operation is\n\
successful, the file system can be mounted using `mount(8)'.\n\
",
         pszProgramName);
   }
   exit(status);
}


int main(int argc, char * * argv)
{
    int c;
    Bool fForceMount = FALSE;
    Bool fReadOnly = FALSE;
    Bool fLazyWrite = TRUE;
    char szKey[1024], * pszKey = 0, * pszBasePath;
    struct sockaddr_in addr;
    struct timeval time;
    int socket;
    CLIENT * clnt;
    addfsargs args;
    addfsres * res;
    int ret = 1;
    int uid = 0, gid = 0, mode = 0600;

    struct option const options[] = {
        { "help", no_argument, 0, 1 },
        { "version", no_argument, 0, 2 },
        { "key", required_argument, 0, 'k' },
        { "force", no_argument, 0, 'f' },
        { "readonly", no_argument, 0, 'r' },
        { "uid", required_argument, 0, 'u' },
        { "gid", required_argument, 0, 'g' },
        { "mode", required_argument, 0, 'm' },
        { "lazy", required_argument, 0, 11 },
        { 0, 0, 0, 0 } 
    };      

    /* Parse the arguments. */
   
    pszProgramName = argv[0];

    while ((c = getopt_long(argc, argv, "fg:k:m:ru:", options, 0)) != EOF) {
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
                fForceMount = TRUE;
                break;

            case 'r': /* --readonly */
                fReadOnly = TRUE;
                break;

            case 'u': /* --uid */
                if (sscanf(optarg, "%d", &uid) != 1) {
                    fprintf(stderr, "%s: invalid uid parameter %s", 
                        pszProgramName, optarg);
                    printUsage(1);
                }
                break;

            case 'g': /* --gid */
                if (sscanf(optarg, "%d", &gid) != 1) {
                    fprintf(stderr, "%s: invalid gid parameter %s", 
                        pszProgramName, optarg);
                    printUsage(1);
                }
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
                    fLazyWrite = TRUE;
                else if (strcmp(optarg, "off") == 0) 
                    fLazyWrite = FALSE;
                else {
                    fprintf(stderr, 
                        "%s: invalid argument to --lazy: %s", 
                        pszProgramName, optarg);
                    printUsage(1);
                }
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
    addr.sin_port = htons(2050);
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
    args.stor_uid = uid;
    args.stor_gid = gid;
    args.stor_mode = mode;
    args.fs_uid = uid ? uid : -1;
    args.fs_gid = gid ? gid : -1;
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
            switch (res->cr) {
                case CORERC_BAD_CHECKSUM:
                    fprintf(stderr, "%s: invalid key\n",
                        pszProgramName);
                    break;
                case CORERC_STORAGE:
                    fprintf(stderr, "%s: I/O error "
                        "accessing the cipher text\n",
                        pszProgramName);
                    break;
                default:
                    fprintf(stderr, "%s: aefsnfsd returned core error %d\n",
                        pszProgramName, res->cr);
            }
            break;
        case ADDFS_DIRTY:
            fprintf(stderr, "%s: file system is dirty, "
                "run `aefsck -f %s' and retry\n",
                pszProgramName, pszBasePath);
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
