/* aefsdmn.c -- Daemon main program.  Gets requests from the ring 0
   IFS and dispatches them to the various worker routines in the other
   C files in this directory.  Also implements the lazy writer.
   Copyright (C) 1999 Eelco Dolstra (edolstra@students.cs.uu.nl).

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
#include <stdarg.h>
#include <string.h>
#include <time.h>

#define INCL_DOSSEMAPHORES
#define INCL_DOSPROCESS
#define INCL_DOSMISC
#define INCL_DOSERRORS
#include <os2.h>

#include "getopt.h"

#include "aefsdmn.h"
#include "sysdep.h"


char * pszProgramName;


int loglevel = 7;


#define LOCKSEM_TIMEOUT 60000 /* 1 min */


/* Format and write a message to stderr if level <= loglevel. */
void logMsg(int level, char * pszMsg, ...)
{
   time_t now;
   char szTime[128];
   va_list args;
   if (level > loglevel) return;
   va_start(args, pszMsg);
   time(&now);
   strftime(szTime, sizeof(szTime),
      "%a, %d %b %Y %H:%M:%S",
      gmtime(&now));
   fprintf(stderr, "[%s] %d: ", szTime, level);
   vfprintf(stderr, pszMsg, args);
   fprintf(stderr, "\n");
   fflush(stderr);
   va_end(args);
}


static void printDaemonStats(ServerData * pServerData)
{
   VolData * pVolData;
   CryptedVolumeStats stats;
   
   fprintf(stderr, "*** INFO ***\n");
   fprintf(stderr, "secure alloced = %9d / %9d\n",
      cbSecureAlloced, cSecureAlloced);
   fprintf(stderr, "secure freed   = %9d / %9d\n",
      cbSecureFreed, cSecureFreed);
   fprintf(stderr, "secure in use  = %9d / %9d\n",
      cbSecureAlloced - cbSecureFreed,
      cSecureAlloced - cSecureFreed);
         
   for (pVolData = pServerData->pFirstVolume;
        pVolData;
        pVolData = pVolData->pNext)
   {
      fprintf(stderr, "drive %c:\n", pVolData->chDrive);
      fprintf(stderr, "  cOpenFiles        = %d\n",
         pVolData->cOpenFiles);
      fprintf(stderr, "  cSearches         = %d\n",
         pVolData->cSearches);
      fprintf(stderr, "  dirty             = %d\n",
         pVolData->pSuperBlock->flFlags & SBF_DIRTY);
      coreQueryVolumeStats(pVolData->pVolume, &stats);
      fprintf(stderr, "  cCryptedFiles     = %d\n",
         stats.cCryptedFiles);
      fprintf(stderr, "  cOpenStorageFiles = %d\n",
         stats.cOpenStorageFiles);
      fprintf(stderr, "  csInCache         = %d\n",
         stats.csInCache);
      fprintf(stderr, "  csDirty           = %d\n",
         stats.csDirty);
   }

   fflush(stderr);
}


static void printUsage(int status)
{
   if (status)
      fprintf(stderr,
         "\nTry `%s --help' for more information.\n",
         pszProgramName);
   else {
      printf("\
Usage: %s [OPTION]...\n\
Start the AEFS daemon.\n\
\n\
  --logfile=FILE        log messages to FILE\n\
  --loglevel=N          set severity level for logging messages\n\
  --cache=N             max cache size per volume in 512 byte units\n\
  --storagefiles=N      max open storage files per volume\n\
  --files=N             max cached files per volume\n\
  --lastaccess=[active|lazy]\n\
                        maintain last-access time stamps normally\n\
                         (default) or lazily\n\
  --lazy=[on|off]       turn lazy writing on (default) or off\n\
  --help                display this help and exit\n\
  --version             output version information and exit\n\
\n\
Note: the number of attached volumes times the maximum number of open\n\
storage files per volume should not exceed %d.\n\
\n\
The daemon's options can be changed while the daemon is running by\n\
using the aefsparm program, which passes its arguments verbatim to the\n\
daemon.\n\
",
         pszProgramName, OPEN_FILES_LIMIT - 16 /* safe margin */);
   }
   exit(status);
}


/* Process program arguments. */
int processArgs(ServerData * pServerData, int argc, char * * argv,
   int startup)
{
   int c;
   
   struct option options[] = {
      { "help", no_argument, 0, 1 },
      { "version", no_argument, 0, 2 },
      { "logfile", required_argument, 0, 3 },
      { "loglevel", required_argument, 0, 4 },
      { "cache", required_argument, 0, 5 },
      { "storagefiles", required_argument, 0, 6 },
      { "files", required_argument, 0, 7 },
      { "quit", no_argument, 0, 8 },
      { "info", no_argument, 0, 9 },
      { "lastaccess", required_argument, 0, 10 },
      { "lazy", required_argument, 0, 11 },
      { 0, 0, 0, 0 } 
   };

   optind = 0;
   while ((c = getopt_long(argc, argv, "", options, 0)) != EOF) {
      switch (c) {
         case 0:
            break;

         case 1: /* --help */
            if (startup) printUsage(0);
            else return 1;

         case 2: /* --version */
            logMsg(0, "aefsdmn - %s", AEFS_VERSION);
            return 1;

         case 3: /* --logfile */
            fclose(stderr);
            if (freopen(optarg, "a", stderr) == 0) {
               logMsg(L_ERR, "cannot open %s as stderr", optarg);
               return 1;
            }
            break;

         case 4: /* --loglevel */
            loglevel = atoi(optarg);
            if (loglevel < 1) loglevel = 1;
            break;

         case 5: /* --cache */
            pServerData->csMaxCached = atoi(optarg);
            if (pServerData->csMaxCached < 1) {
               logMsg(L_ERR, "--cache argument too low");
               pServerData->csMaxCached = 1;
               return 1;
            }
            break;

         case 6: /* --storagefiles */
            pServerData->cMaxOpenStorageFiles = atoi(optarg);
            if (pServerData->cMaxOpenStorageFiles < 1) {
               logMsg(L_ERR, "--storagefiles argument too low");
               pServerData->cMaxOpenStorageFiles = 1;
               return 1;
            }
            break;

         case 7: /* --files */
            pServerData->cMaxCryptedFiles = atoi(optarg);
            break;

         case 8: /* --quit */
            pServerData->fQuit = TRUE;
            break;

         case 9: /* --info */
            printDaemonStats(pServerData);
            break;

         case 10: /* --lastaccess */
            if (strcmp(optarg, "active") == 0) 
               pServerData->fLazyLastAccess = FALSE;
            else if (strcmp(optarg, "lazy") == 0) 
               pServerData->fLazyLastAccess = TRUE;
            else {
               logMsg(L_ERR, "invalid argument to --lastaccess: %s", optarg);
               return 1;
            }
            break;

         case 11: /* --lazy */
            if (strcmp(optarg, "on") == 0) 
               pServerData->fLazyWrite = TRUE;
            else if (strcmp(optarg, "off") == 0) 
               pServerData->fLazyWrite = FALSE;
            else {
               logMsg(L_ERR, "invalid argument to --lazy: %s", optarg);
               return 1;
            }
            break;

         default:
            if (startup) printUsage(1);
            else return 1;
      }
   }

   return 0;
}


/* Allocate the buffers that will be used to pass data between the FSD
   and the daemon. */
static int allocExchangeBuffers(ServerData * pServerData)
{
   APIRET rc;
   
   rc = DosAllocMem((PVOID) &pServerData->pRequest, sizeof(FSREQUEST),
      PAG_COMMIT | OBJ_TILE | PAG_READ | PAG_WRITE);
   if (rc) {
      logMsg(L_FATAL, "error allocating request buffer, rc=%d", rc);
      return 1;
   }
   
   rc = DosAllocMem((PVOID) &pServerData->pData, sizeof(FSDATA),
      PAG_COMMIT | OBJ_TILE | PAG_READ | PAG_WRITE);
   if (rc) {
      logMsg(L_FATAL, "error allocating data buffer, rc=%d", rc);
      return 1;
   }

   return 0;
}


/* Free the exchange buffers. */
static int freeExchangeBuffers(ServerData * pServerData)
{
   APIRET rc;
   int res = 0;

   rc = DosFreeMem(pServerData->pData);
   if (rc) {
      logMsg(L_EVIL, "error freeing data buffer, rc=%d", rc);
      res = 1;
   }
   
   rc = DosFreeMem(pServerData->pRequest);
   if (rc) {
      logMsg(L_EVIL, "error freeing request buffer, rc=%d", rc);
      res = 1;
   }

   return res;
}


/* Announce to the FSD that the daemon is up and running.  The FSD
   will lock the exchange buffers. */
static int announceDaemon(ServerData * pServerData)
{
   APIRET rc;
   SETXCHGBUFFERS buffers;
   ULONG cbParm;
   
   buffers.pRequest = pServerData->pRequest;
   buffers.pData = pServerData->pData;

   cbParm = sizeof(buffers);
      
   rc = DosFSCtl(
      NULL, 0, NULL,
      &buffers, sizeof(buffers), &cbParm,
      FSCTL_STUBFSD_DAEMON_STARTED,
      (PSZ) AEFS_IFS_NAME,
      (HFILE) -1,
      FSCTL_FSDNAME);
   if (rc) {
      logMsg(L_FATAL, "error announcing daemon to FSD, rc=%d", rc);
      return 1;
   }
   
   return 0;
}


/* Tell the FSD that the daemon is going down.  This unlocks the
   exchange buffers. */
static int detachDaemon(ServerData * pServerData)
{
   APIRET rc;
   
   rc = DosFSCtl(
      NULL, 0, NULL,
      NULL, 0, NULL,
      FSCTL_STUBFSD_DAEMON_STOPPED,
      (PSZ) AEFS_IFS_NAME,
      (HFILE) -1,
      FSCTL_FSDNAME);
   if (rc) {
      logMsg(L_EVIL, "error detaching daemon from FSD, rc=%d", rc);
      return 1;
   }
   
   return 0;
}


/* Create the global mutex semaphore that protects against concurrent
   access to the CryptedVolumes. */
static int createGlobalMutex(ServerData * pServerData)
{
   APIRET rc;
   
   rc = DosCreateMutexSem(0, &pServerData->hmtxGlobal, 0, 0);
   if (rc) {
      logMsg(L_FATAL, "error creating global mutex, rc=%d", rc);
      return 1;
   }

   return 0;
}


/* Destroy the global mutex semaphore. */
static int destroyGlobalMutex(ServerData * pServerData)
{
   APIRET rc;

   rc = DosCloseMutexSem(pServerData->hmtxGlobal);
   if (rc) {
      logMsg(L_EVIL, "error destroying global mutex, rc=%d", rc);
      return 1;
   }

   return 0;
}


static void flushAllVolumes(ServerData * pServerData)
{
   APIRET rc;
   VolData * pVolData;
   
   for (pVolData = pServerData->pFirstVolume;
        pVolData;
        pVolData = pVolData->pNext)
   {
      rc = commitVolume(pVolData);
      if (rc) 
         logMsg(L_ERR, "error lazy writing volume, rc=%d", rc);
   }
}


/* Lazy writer thread.  Periodically flush dirty sectors to disk. */
static void lazyWriter(void * arg)
{
   APIRET rc;
   ServerData * pServerData = (ServerData *) arg;

   while ((rc = DosWaitEventSem(pServerData->hevLazyWriterDie,
      5000)) == ERROR_TIMEOUT)
   {
      rc = DosRequestMutexSem(pServerData->hmtxGlobal, LOCKSEM_TIMEOUT);
      if (rc) {
         logMsg(L_ERR,
            "lazy writer thread cannot get exclusive access, rc=%d",
            rc);
         continue;
      }

      flushAllVolumes(pServerData);

      DosReleaseMutexSem(pServerData->hmtxGlobal);
   }

   if (rc) logMsg(L_EVIL,
      "unexpected DosEventSem() error in lazy writer, rc=%d", rc);
   logMsg(L_DBG, "lazy writer is dying");
}


/* Start the lazy writer thread. */
static int startLazyWriter(ServerData * pServerData)
{
   APIRET rc;
   
   rc = DosCreateEventSem(0, &pServerData->hevLazyWriterDie, 0, 0);
   if (rc) {
      logMsg(L_FATAL, "error creating global mutex, rc=%d", rc);
      return 1;
   }
   
   pServerData->tidLazyWriter =
      _beginthread(lazyWriter, 0, 256 * 1024, pServerData);
   if (pServerData->tidLazyWriter == (TID) -1) {
      DosCloseEventSem(pServerData->hevLazyWriterDie);
      logMsg(L_FATAL, "error starting lazy writer thread, errno = %d",
         errno);
      return 1;
   }

   return 0;
}


/* Stop the lazy writer thread. */
static int stopLazyWriter(ServerData * pServerData)
{
   APIRET rc;
   TID tid;

   rc = DosPostEventSem(pServerData->hevLazyWriterDie);
   if (rc) {
      logMsg(L_EVIL,
         "cannot signal lazy writer termination, rc=%d", rc);
      return 1;
   }

   tid = pServerData->tidLazyWriter;
   rc = DosWaitThread(&tid, DCWW_WAIT);
   if (rc) {
      logMsg(L_EVIL,
         "cannot wait for lazy writer termination, rc=%d", rc);
      return 1;
   }

   rc = DosCloseEventSem(pServerData->hevLazyWriterDie);
   if (rc) {
      logMsg(L_EVIL, "error destroying event semaphore, rc=%d", rc);
      return 1;
   }
   
   return 0;
}


/* Initialize the daemon. */
static int initDaemon(ServerData * pServerData)
{
   DosError(FERR_DISABLEHARDERR | FERR_ENABLEEXCEPTION);

   DosSetCurrentDir((PSZ) "\\");

   sysInitPRNG();
   if (allocExchangeBuffers(pServerData)) goto bad1;
   if (announceDaemon(pServerData)) goto bad2;
   if (createGlobalMutex(pServerData)) goto bad3;
   if (startLazyWriter(pServerData)) goto bad4;
   return 0;

bad4:
   destroyGlobalMutex(pServerData);
bad3:
   detachDaemon(pServerData);
bad2:
   freeExchangeBuffers(pServerData);
bad1:
   return 1;
}


/* Deinitialize the daemon. */
static int doneDaemon(ServerData * pServerData)
{
   stopLazyWriter(pServerData);
   destroyGlobalMutex(pServerData);
   detachDaemon(pServerData);
   freeExchangeBuffers(pServerData);
   return 0;
}


/* Block until the FSD places a request in the exchange buffers. */
static int getNextRequest(ServerData * pServerData)
{
   APIRET rc;
   
   rc = DosFSCtl(
      NULL, 0, NULL,
      NULL, 0, NULL,
      FSCTL_STUBFSD_GET_REQUEST,
      (PSZ) AEFS_IFS_NAME,
      (HFILE) -1,
      FSCTL_FSDNAME);
   if (rc) {
      logMsg(L_FATAL, "error getting next request from FSD, rc=%d", rc);
      return 1;
   }

   return 0;
}


/* Signal to the FSD that the request has completed. */
static int signalRequestDone(ServerData * pServerData)
{
   APIRET rc;
   
   rc = DosFSCtl(
      NULL, 0, NULL,
      NULL, 0, NULL,
      FSCTL_STUBFSD_DONE_REQUEST,
      (PSZ) AEFS_IFS_NAME,
      (HFILE) -1,
      FSCTL_FSDNAME);
   if (rc) {
      logMsg(L_FATAL, "error signalling request completion to FSD, rc=%d", rc);
      return 1;
   }

   return 0;
}


/* Execute a request from the FSD. */
static void handleRequest(ServerData * pServerData)
{
   APIRET rc;
   PFSREQUEST pRequest = pServerData->pRequest;
   
   logMsg(L_DBG, "/----- FSD request, code = %d", pRequest->rq);

   switch (pRequest->rq) {

      case FSRQ_FSCTL:
         rc = fsFsCtl(pServerData, &pRequest->data.fsctl);
         break;
         
      case FSRQ_ATTACH:
         rc = fsAttach(pServerData, &pRequest->data.attach);
         break;

      case FSRQ_IOCTL:
         rc = fsIOCtl(pServerData, &pRequest->data.ioctl);
         break;

      case FSRQ_FSINFO:
         rc = fsFsInfo(pServerData, &pRequest->data.fsinfo);
         break;

      case FSRQ_FLUSHBUF:
         rc = fsFlushBuf(pServerData, &pRequest->data.flushbuf);
         break;

      case FSRQ_SHUTDOWN:
         rc = fsShutdown(pServerData, &pRequest->data.shutdown);
         break;

      case FSRQ_OPENCREATE:
         rc = fsOpenCreate(pServerData, &pRequest->data.opencreate);
         break;

      case FSRQ_CLOSE:
         rc = fsClose(pServerData, &pRequest->data.close);
         break;

      case FSRQ_READ:
         rc = fsRead(pServerData, &pRequest->data.read);
         break;

      case FSRQ_WRITE:
         rc = fsWrite(pServerData, &pRequest->data.write);
         break;

      case FSRQ_CHGFILEPTR:
         rc = fsChgFilePtr(pServerData, &pRequest->data.chgfileptr);
         break;

      case FSRQ_NEWSIZE:
         rc = fsNewSize(pServerData, &pRequest->data.newsize);
         break;

      case FSRQ_FILEATTRIBUTE:
         rc = fsFileAttribute(pServerData,
            &pRequest->data.fileattribute);
         break;

      case FSRQ_FILEINFO:
         rc = fsFileInfo(pServerData, &pRequest->data.fileinfo);
         break;

      case FSRQ_COMMIT:
         rc = fsCommit(pServerData, &pRequest->data.commit);
         break;

      case FSRQ_PATHINFO:
         rc = fsPathInfo(pServerData, &pRequest->data.pathinfo);
         break;

      case FSRQ_DELETE:
         rc = fsDelete(pServerData, &pRequest->data.delete);
         break;

      case FSRQ_MOVE:
         rc = fsMove(pServerData, &pRequest->data.move);
         break;

      case FSRQ_COPY:
         rc = ERROR_CANNOT_COPY;
         break;

      case FSRQ_CHDIR:
         rc = fsChDir(pServerData, &pRequest->data.chdir);
         break;

      case FSRQ_MKDIR:
         rc = fsMkDir(pServerData, &pRequest->data.mkdir);
         break;

      case FSRQ_RMDIR:
         rc = fsRmDir(pServerData, &pRequest->data.rmdir);
         break;

      case FSRQ_FINDFIRST:
         rc = fsFindFirst(pServerData, &pRequest->data.findfirst);
         break;

      case FSRQ_FINDNEXT:
         rc = fsFindNext(pServerData, &pRequest->data.findnext);
         break;

      case FSRQ_FINDFROMNAME:
         rc = fsFindFromName(pServerData,
            &pRequest->data.findfromname);
         break;

      case FSRQ_FINDCLOSE:
         rc = fsFindClose(pServerData, &pRequest->data.findclose);
         break;

      case FSRQ_PROCESSNAME:
         rc = fsProcessName(pServerData, &pRequest->data.processname);
         break;

      default:
         logMsg(L_EVIL, "unknown FSD request: %d", pRequest->rq);
         rc = ERROR_NOT_SUPPORTED;
   }

   pRequest->rc = rc;
   
   logMsg(L_DBG, "\\----- FSD request done, result = %d", rc);
}
 

static int runDaemon(ServerData * pServerData)
{
   APIRET rc;
   
   while (!pServerData->fQuit) {
      if (getNextRequest(pServerData)) return 1;

      rc = DosRequestMutexSem(pServerData->hmtxGlobal, LOCKSEM_TIMEOUT);
      if (rc) {
         logMsg(L_ERR,
            "worker thread cannot get exclusive access, rc=%d",
            rc);
         pServerData->pRequest->rc = rc;
         goto done;
      }

      handleRequest(pServerData);

      if (!pServerData->fLazyWrite)
         flushAllVolumes(pServerData);
      
      DosReleaseMutexSem(pServerData->hmtxGlobal);

   done:      
      if (signalRequestDone(pServerData)) return 1;
   }
   
   return 0;
}


int main(int argc, char * * argv)
{
   ServerData serverData;
   int res = 0;

   pszProgramName = argv[0];

   memset(&serverData, 0, sizeof(serverData));
   serverData.pFirstVolume = 0;
   serverData.cMaxOpenStorageFiles = 16;
   serverData.csMaxCached = 4096;
   serverData.cMaxCryptedFiles = 4096;
   serverData.fLazyLastAccess = FALSE;
   serverData.fLazyWrite = TRUE;

   if (processArgs(&serverData, argc, argv, 1)) return 2;
   if (initDaemon(&serverData)) return 1;
   if (runDaemon(&serverData)) res = 1;
   if (doneDaemon(&serverData)) res = 1;

   return res;
}
