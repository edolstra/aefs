/* stubfsd.c -- Ring 0 IFS stub.  Passes requests to the ring 3 daemon.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: stubfsd.c,v 1.5 2001/09/23 13:30:15 eelco Exp $

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

#define INCL_DOSERRORS
#include <os2.h>

#include "dhcalls.h"
#include "fsd.h"
#include "fsh.h"

#define RING0
#include "stubfsd.h"

#undef FS_ATTACH


/* void memcpy(void * p, void * q, int b); */


/* Calling protocol for FSD functions. */
#define IFSEXPORT far pascal _export _loadds

/* Entrypoint to the kernel's device helpers. */
PFN Device_Help;

/* Exported (see stubfsd.def) variables. */
char pascal FS_NAME[] = "STUBFSD\000\000\000\000";
ULONG pascal FS_ATTRIBUTE = FSA_REMOTE;

/* The pid if the daemon process.  0 = no daemon is currently
   attached. */
PID pidDaemon;

typedef unsigned long SEM;

/* This mutex semaphore serializes access to the exchange buffers. */
SEM semSerialize;

/* The daemon can block on this event semaphore to wait for the next
   request; processes signal the availability of a request in the
   exchange buffers by posting (clearing) this semaphore. */
SEM semRqAvail;

/* The daemon posts (clears) this event semaphore to signal completion
   of the request in the exchange buffers to a process. */
SEM semRqDone;

/* If the requesting thread is interrupted before the daemon completes
   the request, then the reply will be lost.  In that case we will set
   this flag so that the daemon will know about it. */ 
int fCallerInterrupted;

/* Lock handles for the exchange buffers. */
typedef char HVMLOCK[12];
HVMLOCK ahvmlock[2];

/* Exchange buffers */
PFSREQUEST pRequest;
PFSDATA    pFSData;


/* Christ!  The kernel sometimes passes "null" pointers that are
   not actually null.  Thanks to Karl Olsen's RAMFS for showing
   this. */
#define IS_NULL(p) (SELECTOROF(p) < 4)


/* Generate an internal processing error, displaying the specified
   error message. */
static void panic(char far * pszMsg)
{
   FSH_INTERR(pszMsg, strlen(pszMsg));
}


/* Macro: prepend the FSD's name to the specified IPE message. */
#define PANIC(msg) panic("STUBFSD: " msg)


/* Map a virtual (16:16) pointer to a linear (0:32) pointer. */
LIN virtToLin(void far * p)
{
   int rc;
   LIN lin;
   rc = DevHelp_VirtToLin(
      SELECTOROF(p),
      OFFSETOF(p),
      &lin);
   if (rc) PANIC("virtToLin failed!");
   return lin;
}


/* Return the process identifier of the calling process. */
static PID queryCurrentPid()
{
   int rc;
   struct {
         PID pid;
         unsigned short uid;
         unsigned short pdb;
   } info;

   rc = FSH_QSYSINFO(QSI_PROCID, (char far *) &info, sizeof info);
   if (rc) PANIC("Cannot query PID!");

   return info.pid;
}


/* Acquire exclusive access to the exchange buffers and the event
   semaphores. */
static int requestExchangeXS()
{
   int rc;

   if (!pidDaemon)
      return ERROR_STUBFSD_DAEMON_NOT_RUNNING;

   if (queryCurrentPid() == pidDaemon)
      return ERROR_STUBFSD_DEADLOCK; /* deadlock prevented */

   /* The daemon could still be accessing the exchange buffers; this
      happens if the previous requesting thread was interrupted.  So
      wait until the daemon is done with the previous request. */
   rc = FSH_SEMWAIT(&semRqDone, TO_INFINITE);
   if (rc) return rc;

   rc = FSH_SEMREQUEST(&semSerialize, TO_INFINITE);
   if (rc) return rc;

   if (!pidDaemon) { /* the daemon just died */
      FSH_SEMCLEAR(&semSerialize);
      return ERROR_STUBFSD_DAEMON_NOT_RUNNING;
   }

   return NO_ERROR;
}


/* Release exclusive access to the exchange buffers. */
static int releaseExchangeXS()
{
   return FSH_SEMCLEAR(&semSerialize);
}


/* Signal to the daemon that a request is available in the exchange
   buffers, and block until the daemon signals that is has completed
   the request. */
static int signalDaemonAndWait()
{
   int rc;

   rc = FSH_SEMSET(&semRqDone);
   if (rc) return rc;

   fCallerInterrupted = 0;

   rc = FSH_SEMCLEAR(&semRqAvail);
   if (rc) return rc;

   rc = FSH_SEMWAIT(&semRqDone, TO_INFINITE);
   /* We could be interrupted prematurely (ERROR_INTERRUPT).  If so,
      we still release semSerialize, since requestExchangeXS() will
      wait for semRqDone to clear anyway. */
   if (rc) {
       fCallerInterrupted = 1;
       return rc;
   }

   if (!pidDaemon)
      return ERROR_STUBFSD_DAEMON_NOT_RUNNING;

   return NO_ERROR;
}


/* Return a pointer to the specified volume's FSD-dependent volume
   data. */
static VPFSD far * queryVPFSD(unsigned short hVPB)
{
   struct vpfsi far * pvpfsi;
   struct vpfsd far * pvpfsd;
   FSH_GETVOLPARM(hVPB, &pvpfsi, &pvpfsd);
   if (!pvpfsd) PANIC("Invalid VPB handle!");
   return (VPFSD far *) pvpfsd;
}


/* Called when the daemon is initializing.  Lock exchange buffers.
   This had better not fail, because we do not recover gracefully from
   errors. */
static APIRET daemonStarted(PSETXCHGBUFFERS pxchg)
{
   APIRET rc;
   PAGELIST pagelist[17];
   ULONG cPages;
   
   /* Lock the request buffer. */
   rc = DevHelp_VMLock(
      VMDHL_WRITE | VMDHL_LONG,
      pxchg->linRequest,
      sizeof(FSREQUEST),
      virtToLin(pagelist),
      virtToLin(&ahvmlock[0]),
      &cPages);
   if (rc) return ERROR_STUBFSD_INIT_FAILED;

   /* Map the request buffer to a 16:16 address. */
   rc = DevHelp_LinToGDTSelector(
      SELECTOROF(pRequest),
      pxchg->linRequest,
      sizeof(FSREQUEST));
   if (rc) return ERROR_STUBFSD_INIT_FAILED;

   /* Lock the data buffer. */
   rc = DevHelp_VMLock(
      VMDHL_WRITE | VMDHL_LONG,
      pxchg->linData,
      sizeof(FSDATA),
      virtToLin(pagelist),
      virtToLin(&ahvmlock[1]),
      &cPages);
   if (rc) return ERROR_STUBFSD_INIT_FAILED;

   /* Map the data buffer to a 16:16 address. */
   rc = DevHelp_LinToGDTSelector(
      SELECTOROF(pFSData),
      pxchg->linData,
      sizeof(FSDATA));
   if (rc) return ERROR_STUBFSD_INIT_FAILED;

   pidDaemon = queryCurrentPid();

   /* Set up the semaphores. */
   rc = FSH_SEMSET(&semRqAvail);
   if (rc) return rc;
   
   rc = FSH_SEMCLEAR(&semRqDone);
   if (rc) return rc;
   
   rc = FSH_SEMCLEAR(&semSerialize);
   if (rc) return rc;
}


/* Called when the daemon is terminating.  Unblock all threads that
   are blocked in the FSD.  Unlock the exchange buffers. */
static APIRET daemonStopped()
{
   int rc;

   /* This will cause any thread subsequently entering
      requestExchangeXS() to immediately return with a
      ERROR_STUBFSD_DAEMON_NOT_RUNNING error code. */
   pidDaemon = 0;

   /* Post the operation-done semaphore.  This will cause the thread
      blocked in signalDaemonAndWait() to wake up, if there is one.
      It will notice the daemon's death and release access to the
      exchange buffer.  This will cause a thread blocked in
      requestExchangeXS() to wake up, if there is one. It will also
      notice the daemon's death and release buffer access, causing the
      next waiting thread to wake up, etc.  Thus, all blocked threads
      will unblock and return. */
   FSH_SEMCLEAR(&semRqDone);

   /* Now we have to wait until we have exclusive access to the
      exchange buffers (which happens after all blocked threads have
      exited).  If we don't, unlocking and freeing them could cause a
      panic when some thread tries to access a buffer because it thinks
      it's still valid. (???) */
   rc = FSH_SEMREQUEST(&semSerialize, TO_INFINITE);
   if (rc) return rc;

   DevHelp_VMUnLock(virtToLin(ahvmlock[0]));
   DevHelp_VMUnLock(virtToLin(ahvmlock[1]));

   rc = FSH_SEMCLEAR(&semSerialize);
   if (rc) return rc;

   return NO_ERROR;
}


int IFSEXPORT
FS_INIT(
   char far * pszParm,
   unsigned long pDevHlp,
   unsigned long far * pMiniFSD
   )
{
   int rc;
   SEL aselMapping[2];
   char far * p;
   int i;

   Device_Help = (PFN) pDevHlp;

   pidDaemon = 0;

   /* Parse the IFS name. */
   p = pszParm;
   while ((*p == ' ') || (*p == '\t')) p++;
   if (*p) {
      for (i = 0;
           (i < sizeof(FS_NAME)) &&
              (*p) &&
              (*p != ' ') &&
              (*p != '\t');
           i++)
         FS_NAME[i] = *p++;
      FS_NAME[i] = 0;
   }
   
   /* Allocate enough GDT selectors. */
   rc = DevHelp_AllocGDTSelector(aselMapping, 2);
   if (rc) return rc;

   pRequest = MAKEP(aselMapping[0], 0);
   pFSData = MAKEP(aselMapping[1], 0);

   return NO_ERROR;
}


#define RELEASE_AND_EXIT(rcexpr) \
   { \
      int foo, foo2; \
      foo2 = rcexpr; \
      foo = releaseExchangeXS(); \
      return foo ? foo : foo2; \
   }

#define COPYPTR(dst, src) \
   * (ULONG far * far *) (dst) = * (ULONG far * far *) (src)

     
/* Note: FS_FSCTL copies the parameter buffer to the exchange buffer
   on entry, and copies the exchange buffer to the data buffer on
   exit.  Therefore, the data buffer cannot be used to pass input to
   the FSD, and the parameter buffer cannot be used to pass output
   to the caller. */

int IFSEXPORT
FS_FSCTL(
   union argdat far * pArgDat,
   unsigned short iArgType,
   unsigned short usFunc,
   char far * pParm,
   unsigned short cbMaxParm,
   unsigned short far * pcbParm,
   char far * pData,
   unsigned short cbMaxData,
   unsigned short far * pcbData
   )
{
   int rc;
   struct fsctl far * p = &pRequest->data.fsctl;
   int f;

   /* Validate iArgType. */
   if ((iArgType != FSCTL_ARG_FILEINSTANCE) &&
       (iArgType != FSCTL_ARG_CURDIR) &&
       (iArgType != FSCTL_ARG_NULL))
      return ERROR_NOT_SUPPORTED;

   /* Validate the parameter buffer. */
   if (cbMaxParm) {
      rc = FSH_PROBEBUF(PB_OPREAD, (char far *) pcbParm,
         sizeof(USHORT));
      if (rc) return ERROR_INVALID_PARAMETER;
      if (*pcbParm > cbMaxParm) return ERROR_INVALID_PARAMETER;
      if (*pcbParm) {
         rc = FSH_PROBEBUF(PB_OPREAD, pParm, *pcbParm);
         if (rc) return ERROR_INVALID_PARAMETER;
      }
   }

   switch (usFunc) {

      case FSCTL_STUBFSD_DAEMON_STARTED: /* daemon started */
      
         if (pidDaemon) return ERROR_STUBFSD_DAEMON_RUNNING;

         if (*pcbParm != sizeof(SETXCHGBUFFERS))
            return ERROR_INVALID_PARAMETER;

         return daemonStarted((PSETXCHGBUFFERS) pParm);

      case FSCTL_STUBFSD_DAEMON_STOPPED: /* daemon stopped */
      
         if (!pidDaemon)
            return ERROR_STUBFSD_DAEMON_NOT_RUNNING;

         if (queryCurrentPid() != pidDaemon)
            return ERROR_STUBFSD_NOT_DAEMON;

         return daemonStopped();

      case FSCTL_STUBFSD_RESET: /* forcibly detach daemon */
      
         return daemonStopped();

      case FSCTL_STUBFSD_GET_REQUEST: /* wait for next request */

         if (queryCurrentPid() != pidDaemon)
            return ERROR_STUBFSD_NOT_DAEMON;

         rc = FSH_SEMWAIT(&semRqAvail, TO_INFINITE);
         if (rc) return rc;
         
         rc = FSH_SEMSET(&semRqAvail);
         if (rc) return rc;

         return NO_ERROR;

      case FSCTL_STUBFSD_DONE_REQUEST: /* signal request done */
      
         if (queryCurrentPid() != pidDaemon)
            return ERROR_STUBFSD_NOT_DAEMON;

         /* After clearing semRqDone we can no longer touch
            fCallerInterrupted. */
         f = fCallerInterrupted;
         
         rc = FSH_SEMCLEAR(&semRqDone);
         if (rc) return rc;

         return f ? ERROR_STUBFSD_CALLER_INTERRUPTED : NO_ERROR;

      default: /* unknown FSCTL, send to daemon */

         if (rc = requestExchangeXS()) return rc;

         pRequest->rq = FSRQ_FSCTL;

         p->iArgType = iArgType;
         p->usFunc = usFunc;
         p->cbParm = cbMaxParm ? *pcbParm : 0;
         p->cbMaxData = cbMaxData;
         p->cbData = 0;

         if (cbMaxParm) memcpy(pFSData, pParm, *pcbParm);

         if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

         if (p->cbData) {
            rc = FSH_PROBEBUF(PB_OPWRITE, (char far *) pcbData,
               sizeof(USHORT));
            if (rc) RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
            *pcbData = p->cbData;
            if (!pRequest->rc) {
               if (*pcbData > cbMaxData)
                  RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
               if (*pcbData) {
                  rc = FSH_PROBEBUF(PB_OPWRITE, pData, *pcbData);
                  if (rc) RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
                  memcpy(pData, pFSData, *pcbData);
               }
            }
         }
         
         RELEASE_AND_EXIT(pRequest->rc);
   }

}


int IFSEXPORT
FS_MOUNT(
   unsigned short flag,
   struct vpfsi far * pvpfsi,
   VPFSD far * pvpfsd,
   unsigned short hVPB,
   char far * pBoot
   )
{
   /* Remote file systems cannot mount local drives. */
   return ERROR_NOT_SUPPORTED;
}


int IFSEXPORT FS_ATTACH(
   unsigned short fsFlag,
   char far * pszDev,
   VPFSD far * pvpfsd,
   CDFSD far * pcdfsd,
   char far * pParm,
   unsigned short far * pcbParm
   )
{
   int rc;
   struct attach far * p = &pRequest->data.attach;

   /* Hack (nice for debugging): this allows us to detach a drive
      after the daemon dies (we cannot safely restart the daemon while
      there are still attached drives, because the daemon will
      then receive invalid pointers (VolData etc.) from the kernel and
      will probably dump core). */
   if (fsFlag == FSA_DETACH && !pidDaemon) {
      return NO_ERROR; /* now the kernel can proceed happily */
   }

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_ATTACH;

   p->fsFlag = fsFlag;

   if (strlen(pszDev) >= FSXCHG_ATTACH_DEVMAX)
      RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
   strcpy(p->szDev, pszDev);

   if (pvpfsd) p->vpfsd = *pvpfsd;
   if (pcdfsd) p->cdfsd = *pcdfsd;

   p->cbParm = *pcbParm;

   if (((fsFlag == FSA_ATTACH) || (fsFlag == FSA_DETACH)) && *pcbParm) {
      rc = FSH_PROBEBUF(PB_OPREAD, pParm, *pcbParm);
      if (rc) RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
      memcpy(pFSData, pParm, *pcbParm);
   }

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   if (fsFlag == FSA_ATTACH_INFO) {
      *pcbParm = p->cbParm;
      if (*pcbParm && !pRequest->rc) {
         rc = FSH_PROBEBUF(PB_OPWRITE, pParm, *pcbParm);
         if (rc) RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
         memcpy(pParm, pFSData, *pcbParm);
      }
   }

   if (pvpfsd) *pvpfsd = p->vpfsd;
   if (pcdfsd) *pcdfsd = p->cdfsd;

   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_IOCTL(
   struct sffsi far * psffsi,
   SFFSD far * psffsd,
   unsigned short usCat,
   unsigned short usFunc,
   char far * pParm,
   unsigned short cbMaxParm,
   unsigned short far * pcbParm,
   char far * pData,
   unsigned short cbMaxData,
   unsigned short far * pcbData
   )
{
   int rc;
   struct ioctl far * p = &pRequest->data.ioctl;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_IOCTL;

   p->vpfsd = *queryVPFSD(psffsi->sfi_hVPB);
   p->sffsi = *psffsi;
   p->sffsd = *psffsd;
   p->usCat = usCat;
   p->usFunc = usFunc;
   p->cbParm = cbMaxParm ? *pcbParm : 0;
   p->cbMaxData = cbMaxData;
   p->cbData = 0;

   /* Validate the parameter buffer. */
   if (cbMaxParm) {
      rc = FSH_PROBEBUF(PB_OPREAD, (char far *) pcbParm,
         sizeof(USHORT));
      if (rc) return ERROR_INVALID_PARAMETER;
      if (*pcbParm > cbMaxParm) return ERROR_INVALID_PARAMETER;
      if (*pcbParm) {
         rc = FSH_PROBEBUF(PB_OPREAD, pParm, *pcbParm);
         if (rc) return ERROR_INVALID_PARAMETER;
      }
      memcpy(pFSData, pParm, *pcbParm);
   }

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   if (p->cbData) {
      rc = FSH_PROBEBUF(PB_OPWRITE, (char far *) pcbData,
         sizeof(USHORT));
      if (rc) RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
      *pcbData = p->cbData;
      if (!pRequest->rc) {
         if (*pcbData > cbMaxData)
            RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
         if (*pcbData) {
            rc = FSH_PROBEBUF(PB_OPWRITE, pData, *pcbData);
            if (rc) RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
            memcpy(pData, pFSData, *pcbData);
         }
      }
   }
         
   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_FSINFO(
   unsigned short fsFlag,
   unsigned short hVPB,
   char far * pData,
   unsigned short cbData,
   unsigned short usLevel
   )
{
   int rc;
   struct fsinfo far * p = &pRequest->data.fsinfo;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_FSINFO;

   p->fsFlag = fsFlag;
   p->vpfsd = *queryVPFSD(hVPB);
   p->cbData = cbData;

   if ((fsFlag == INFO_SET) && cbData) {
      rc = FSH_PROBEBUF(PB_OPREAD, pData, cbData);
      if (rc) RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
      memcpy(pFSData, pData, cbData);
   }

   p->usLevel = usLevel;

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   if ((fsFlag == INFO_RETRIEVE) && !pRequest->rc) {
      cbData = p->cbData;
      if (cbData) {
         rc = FSH_PROBEBUF(PB_OPWRITE, pData, cbData);
         if (rc) RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
         memcpy(pData, pFSData, cbData);
      }
   }

   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_FLUSHBUF(
   unsigned short hVPB,
   unsigned short fsFlag
   )
{
   int rc;
   struct flushbuf far * p = &pRequest->data.flushbuf;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_FLUSHBUF;

   p->vpfsd = *queryVPFSD(hVPB);
   p->fsFlag = fsFlag;
   
   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_SHUTDOWN(
   unsigned short usType,
   unsigned long ulReserved
   )
{
#if 0   
   int rc;
   struct shutdown far * p = &pRequest->data.shutdown;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_SHUTDOWN;

   p->usType = usType;
   
   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   RELEASE_AND_EXIT(pRequest->rc);
#endif
   return NO_ERROR;
}


void IFSEXPORT
FS_EXIT(
   unsigned short uid,
   unsigned short pid,
   unsigned short pdb
   )
{
   if (pidDaemon && (pid == pidDaemon))
      daemonStopped();
}


#define CEA_FEAS_TO_BUF  1
#define CEA_BUF_TO_FEAS  2
#define CEA_GEAS_TO_BUF  8
#define CEA_SET_OERROR   16


static APIRET copyEAOP(PEAOP pEABuf, USHORT usWhat, USHORT oError)
{
   APIRET rc, rcfinal = NO_ERROR;
   PFEALIST pfeas;
   PGEALIST pgeas;
   ULONG cbList;
   
   /* Is the EAOP structure readable? */
   rc = FSH_PROBEBUF(PB_OPREAD, (char far *) pEABuf, sizeof(EAOP));
   if (rc) return ERROR_INVALID_PARAMETER;

   pfeas = pEABuf->fpFEAList;
   pgeas = pEABuf->fpGEAList;

   /* Set the error code? */
   if (usWhat & CEA_SET_OERROR) {

      /* Is the EAOP structure writeable? */
      rc = FSH_PROBEBUF(PB_OPWRITE, (char far *) pEABuf, sizeof(EAOP));
      if (rc) return ERROR_INVALID_PARAMETER;

      pEABuf->oError = oError;
   }

   if ((usWhat & CEA_FEAS_TO_BUF) ||
       (usWhat & CEA_BUF_TO_FEAS))
   {
      /* Can we read the FEA list's cbList member? */
      rc = FSH_PROBEBUF(PB_OPREAD, (char far *) pfeas, sizeof(ULONG));
      if (rc) return ERROR_INVALID_PARAMETER;

      /* Copy FEAs to the data exchange buffer? */
      if (usWhat & CEA_FEAS_TO_BUF) {
         
         /* Is cbList not too small or too big? */
         if (pfeas->cbList < 4) return ERROR_EA_LIST_INCONSISTENT;
         if (pfeas->cbList > 65536) return ERROR_EA_LIST_TOO_LONG;
         
         /* Can we read the entire FEA list? */
         rc = FSH_PROBEBUF(PB_OPREAD, (char far *) pfeas,
            (USHORT) pfeas->cbList);
         if (rc) return ERROR_INVALID_PARAMETER;
         
         /* OK, copy the FEA list. */
         memcpy(pFSData, pfeas, pfeas->cbList);
      }
      
      /* Copy data exchange buffer to the FEA buffer? */
      if (usWhat & CEA_BUF_TO_FEAS) {
         
         cbList = ((PFEALIST) pFSData)->cbList;

         /* Is the FEA buffer big enough?  In not, we copy as much as
            possible and return an overflow error. */
         if ((cbList > 65536) ||
             (cbList > pfeas->cbList)) {
            rcfinal = ERROR_BUFFER_OVERFLOW;
            cbList = pfeas->cbList;
         }

         /* Can we write the entire FEA list? */
         rc = FSH_PROBEBUF(PB_OPWRITE, (char far *) pfeas,
            (USHORT) cbList);
         if (rc) return ERROR_INVALID_PARAMETER;
         
         /* OK, copy the FEA list. */
         memcpy(pfeas, pFSData, cbList);
      }
      
   }

   /* Copy GEAs to the data exchange buffer? */
   if (usWhat & CEA_GEAS_TO_BUF) {
      
      /* Can we read the GEA list's cbList member? */
      rc = FSH_PROBEBUF(PB_OPREAD, (char far *) pgeas, sizeof(ULONG));
      if (rc) return ERROR_INVALID_PARAMETER;

      /* Is cbList not too small or too big? */
      if (pgeas->cbList < 4) return ERROR_EA_LIST_INCONSISTENT;
      if (pgeas->cbList > 65536) return ERROR_EA_LIST_TOO_LONG;
         
      /* Can we read the entire GEA list? */
      rc = FSH_PROBEBUF(PB_OPREAD, (char far *) pgeas,
         (USHORT) pgeas->cbList);
      if (rc) return ERROR_INVALID_PARAMETER;
         
      /* OK, copy the FEA list. */
      memcpy(pFSData, pgeas, pgeas->cbList);
   }
      
   return rc;
}


int IFSEXPORT
FS_OPENCREATE(
   struct cdfsi far * pcdfsi,
   CDFSD far * pcdfsd,
   char far * pszName,
   unsigned short iCurDirEnd,
   struct sffsi far * psffsi,
   SFFSD far * psffsd,
   unsigned long flOpenMode,
   unsigned short fsOpenFlag,
   unsigned short far * pusAction,
   unsigned short fsAttr,
   PEAOP pEABuf,
   unsigned short far * pfsGenFlag
   )
{
   int rc;
   struct opencreate far * p = &pRequest->data.opencreate;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_OPENCREATE;

   p->vpfsd = *queryVPFSD(pcdfsi->cdi_hVPB);
   p->cdfsi = *pcdfsi;
   p->cdfsd = *pcdfsd;

   if (strlen(pszName) >= CCHMAXPATH)
      RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
   strcpy(p->szName, pszName);
   p->iCurDirEnd = iCurDirEnd;

   p->sffsi = *psffsi;
   p->flOpenMode = flOpenMode;
   p->fsOpenFlag = fsOpenFlag;
   p->fsAttr = fsAttr;

   if (!IS_NULL(pEABuf)) {
      rc = copyEAOP(pEABuf, CEA_FEAS_TO_BUF, 0);
      if (rc) RELEASE_AND_EXIT(rc);
      p->fHasEAs = 1;
   }
   else p->fHasEAs = 0;

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   *psffsi = p->sffsi;
   if (psffsi->sfi_type == STYPE_FILE)
      *psffsd = p->sffsd;

   *pusAction = p->usAction;
   *pfsGenFlag = p->fsGenFlag;

   if (!IS_NULL(pEABuf)) {
      rc = copyEAOP(pEABuf, CEA_SET_OERROR, p->oError);
      if (rc) RELEASE_AND_EXIT(rc);
   }

   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_CLOSE(
   unsigned short usType,
   unsigned short fsIOFlag,
   struct sffsi far * psffsi,
   SFFSD far * psffsd
   )
{
   int rc;
   struct close far * p = &pRequest->data.close;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_CLOSE;

   p->vpfsd = *queryVPFSD(psffsi->sfi_hVPB);
   p->usType = usType;
   p->fsIOFlag = fsIOFlag;
   p->sffsi = *psffsi;
   p->sffsd = *psffsd;

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   *psffsi = p->sffsi;

   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_READ(
   struct sffsi far * psffsi,
   SFFSD far * psffsd,
   char far * pData,
   unsigned short far * pcbLen,
   unsigned short fsIOFlag
   )
{
   int rc;
   struct write far * p = &pRequest->data.write;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_READ;

   p->vpfsd = *queryVPFSD(psffsi->sfi_hVPB);
   p->sffsi = *psffsi;
   p->sffsd = *psffsd;
   p->cbLen = *pcbLen;
   p->fsIOFlag = fsIOFlag;

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   *psffsi = p->sffsi;
   
   *pcbLen = p->cbLen;
   if (*pcbLen) {
      rc = FSH_PROBEBUF(PB_OPWRITE, pData, *pcbLen);
      if (rc) RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
      memcpy(pData, pFSData, *pcbLen);
   }

   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_WRITE(
   struct sffsi far * psffsi,
   SFFSD far * psffsd,
   char far * pData,
   unsigned short far * pcbLen,
   unsigned short fsIOFlag
   )
{
   int rc;
   struct write far * p = &pRequest->data.write;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_WRITE;

   p->vpfsd = *queryVPFSD(psffsi->sfi_hVPB);
   p->sffsi = *psffsi;
   p->sffsd = *psffsd;
   p->cbLen = *pcbLen;
   p->fsIOFlag = fsIOFlag;

   if (*pcbLen) {
      rc = FSH_PROBEBUF(PB_OPREAD, pData, *pcbLen);
      if (rc) RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
      memcpy(pFSData, pData, *pcbLen);
   }

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   *psffsi = p->sffsi;
   
   *pcbLen = p->cbLen;
   
   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_FILEIO(
   struct sffsi far * psffsi,
   SFFSD far * psffsd,
   char far * cbCmdList,
   unsigned short pCmdLen,
   unsigned short far * poError,
   unsigned short IOflag
   )
{
   return ERROR_NOT_SUPPORTED; /* will never happen */
}


int IFSEXPORT
FS_CHGFILEPTR(
   struct sffsi far * psffsi,
   SFFSD far * psffsd,
   long ibOffset,
   unsigned short usType,
   unsigned short fsIOFlag
   )
{
   int rc;
   struct chgfileptr far * p = &pRequest->data.chgfileptr;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_CHGFILEPTR;

   p->vpfsd = *queryVPFSD(psffsi->sfi_hVPB);
   p->sffsi = *psffsi;
   p->sffsd = *psffsd;
   p->ibOffset = ibOffset;
   p->usType = usType;
   p->fsIOFlag = fsIOFlag;
   
   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   *psffsi = p->sffsi;
   
   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_NEWSIZE(
   struct sffsi far * psffsi,
   SFFSD far * psffsd,
   unsigned long cbLen,
   unsigned short fsIOFlag
   )
{
   int rc;
   struct newsize far * p = &pRequest->data.newsize;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_NEWSIZE;

   p->vpfsd = *queryVPFSD(psffsi->sfi_hVPB);
   p->sffsi = *psffsi;
   p->sffsd = *psffsd;
   p->cbLen = cbLen;
   p->fsIOFlag = fsIOFlag;
   
   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   *psffsi = p->sffsi;
   
   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_FILEATTRIBUTE(
   unsigned short fsFlag,
   struct cdfsi far * pcdfsi,
   CDFSD far * pcdfsd,
   char far * pszName,
   unsigned short iCurDirEnd,
   unsigned short far * pfsAttr
   )
{
   int rc;
   struct fileattribute far * p = &pRequest->data.fileattribute;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_FILEATTRIBUTE;

   p->vpfsd = *queryVPFSD(pcdfsi->cdi_hVPB);
   p->cdfsi = *pcdfsi;
   p->cdfsd = *pcdfsd;
   
   if (strlen(pszName) >= CCHMAXPATH)
      RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
   strcpy(p->szName, pszName);
   p->iCurDirEnd = iCurDirEnd;

   p->fsFlag = fsFlag;

   if (fsFlag & FA_SET) p->fsAttr = *pfsAttr;

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   if (!(fsFlag & FA_SET) && !pRequest->rc) *pfsAttr = p->fsAttr;

   RELEASE_AND_EXIT(pRequest->rc);
}


/* For FS_FILEINFO and FS_PATHINFO, we pass buffer information in the
   following way:
   For setting level 1 info, we copy pData to pFSData on entry.
   For setting level 2 info, we copy the FEALIST pointed to by the
   EAOP structure in pData to pFSData on entry, and set the EAOP's
   oError field on exit.
   For querying level 1 and 2 info, we copy pFSData to pData on
   exit.
   For querying level 3 info, we copy the GEALIST pointed to by the
   EAOP structure in pData to pFSData on entry, and copy pFSData to
   the FEALIST pointed to by the EAOP structure and set the EAOP's
   oError field on exit.
   For querying level 4 info, we copy pFSData to the FEALIST pointed
   to by the EAOP structure on exit.
   */


static APIRET copyFileInfoBufPre(USHORT fsFlag, USHORT usLevel, 
   USHORT cbData, char far * pData)
{
   APIRET rc;
   
   if (fsFlag & FI_SET) {

      if (usLevel == 2) {
         rc = copyEAOP((PEAOP) pData, CEA_FEAS_TO_BUF, 0);
         if (rc) return rc;
      } else {
         rc = FSH_PROBEBUF(PB_OPREAD, pData, cbData);
         if (rc) RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
         memcpy(pFSData, pData, cbData);
      }
      
   } else {

      if (usLevel == 3) {
         rc = copyEAOP((PEAOP) pData, CEA_GEAS_TO_BUF, 0);
         if (rc) return rc;
      }
      
   }

   return NO_ERROR;
}


static APIRET copyFileInfoBufPost(USHORT fsFlag, USHORT usLevel, 
   USHORT cbData, char far * pData, USHORT oError)
{
   APIRET rc;
   
   if (fsFlag & FI_SET) {

      if (usLevel == 2) {
         rc = copyEAOP((PEAOP) pData, CEA_SET_OERROR, oError);
         if (rc) return rc;
      }
      
   } else {

      if (usLevel == 3) {
         rc = copyEAOP((PEAOP) pData, CEA_BUF_TO_FEAS |
            CEA_SET_OERROR, oError);
         if (rc) return rc;
      } else if (usLevel == 4) {
         rc = copyEAOP((PEAOP) pData, CEA_BUF_TO_FEAS, 0);
         if (rc) return rc;
      } else {
         rc = FSH_PROBEBUF(PB_OPWRITE, pData, cbData);
         if (rc) RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
         memcpy(pData, pFSData, cbData);
      }
      
   }

   return NO_ERROR;
}


int IFSEXPORT
FS_FILEINFO(
   unsigned short fsFlag,
   struct sffsi far * psffsi,
   SFFSD far * psffsd,
   unsigned short usLevel,
   char far * pData,
   unsigned short cbData,
   unsigned short fsIOFlag
   )
{
   int rc, rc2;
   struct fileinfo far * p = &pRequest->data.fileinfo;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_FILEINFO;

   p->vpfsd = *queryVPFSD(psffsi->sfi_hVPB);
   p->sffsi = *psffsi;
   p->sffsd = *psffsd;
   p->fsFlag = fsFlag;
   p->usLevel = usLevel;
   p->cbData = cbData;
   p->fsIOFlag = fsIOFlag;

   copyFileInfoBufPre(fsFlag, usLevel, cbData, pData);

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   *psffsi = p->sffsi;
   
   rc2 = copyFileInfoBufPost(fsFlag, usLevel, cbData, pData,
      p->oError);

   RELEASE_AND_EXIT(pRequest->rc ? pRequest->rc : rc2);
}


int IFSEXPORT
FS_COMMIT(
   unsigned short usType,
   unsigned short fsIOFlag,
   struct sffsi far * psffsi,
   SFFSD far * psffsd
   )
{
   int rc;
   struct commit far * p = &pRequest->data.commit;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_COMMIT;

   p->vpfsd = *queryVPFSD(psffsi->sfi_hVPB);
   p->sffsi = *psffsi;
   p->sffsd = *psffsd;
   p->usType = usType;
   p->fsIOFlag = fsIOFlag;

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   *psffsi = p->sffsi;
   
   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_PATHINFO(
   unsigned short fsFlag,
   struct cdfsi far * pcdfsi,
   CDFSD far * pcdfsd,
   char far * pszName,
   unsigned short iCurDirEnd,
   unsigned short usLevel,
   char far * pData,
   unsigned short cbData
   )
{
   int rc, rc2;
   struct pathinfo far * p = &pRequest->data.pathinfo;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_PATHINFO;

   p->vpfsd = *queryVPFSD(pcdfsi->cdi_hVPB);
   p->cdfsi = *pcdfsi;
   p->cdfsd = *pcdfsd;
   
   if (strlen(pszName) >= CCHMAXPATH)
      RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
   strcpy(p->szName, pszName);
   p->iCurDirEnd = iCurDirEnd;

   p->fsFlag = fsFlag;
   p->usLevel = usLevel;
   p->cbData = cbData;

   copyFileInfoBufPre(fsFlag, usLevel, cbData, pData);

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   rc2 = copyFileInfoBufPost(fsFlag, usLevel, cbData, pData, p->oError);

   RELEASE_AND_EXIT(pRequest->rc ? pRequest->rc : rc2);
}


int IFSEXPORT
FS_DELETE(
   struct cdfsi far * pcdfsi,
   CDFSD far * pcdfsd,
   char far * pszName,
   unsigned short iCurDirEnd
   )
{
   int rc;
   struct delete far * p = &pRequest->data.delete;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_DELETE;

   p->vpfsd = *queryVPFSD(pcdfsi->cdi_hVPB);
   p->cdfsi = *pcdfsi;
   p->cdfsd = *pcdfsd;

   if (strlen(pszName) >= CCHMAXPATH)
      RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
   strcpy(p->szName, pszName);
   p->iCurDirEnd = iCurDirEnd;
   
   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_COPY(
   unsigned short flag,
   struct cdfsi far * pcdfsi,
   CDFSD far * pcdfsd,
   char far * pSrc,
   unsigned short iSrcCurrDirEnd,
   char far * pDst,
   unsigned short iDstCurrDirEnd,
   unsigned short nameType
   )
{
   int rc;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_COPY;

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_MOVE(
   struct cdfsi far * pcdfsi,
   CDFSD far * pcdfsd,
   char far * pszSrc,
   unsigned short iSrcCurDirEnd,
   char far * pszDst,
   unsigned short iDstCurDirEnd,
   unsigned short flags
   )
{
   int rc;
   struct move far * p = &pRequest->data.move;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_MOVE;

   p->vpfsd = *queryVPFSD(pcdfsi->cdi_hVPB);
   p->cdfsi = *pcdfsi;
   p->cdfsd = *pcdfsd;

   if (strlen(pszSrc) >= CCHMAXPATH)
      RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
   strcpy(p->szSrc, pszSrc);
   p->iSrcCurDirEnd = iSrcCurDirEnd;
   
   if (strlen(pszDst) >= CCHMAXPATH)
      RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
   strcpy(p->szDst, pszDst);
   p->iDstCurDirEnd = iDstCurDirEnd;
   
   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_CHDIR(
   unsigned short fsFlag,
   struct cdfsi far * pcdfsi,
   CDFSD far * pcdfsd,
   char far * pszDir,
   unsigned short iCurDirEnd
   )
{
   int rc;
   struct chdir far * p = &pRequest->data.chdir;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_CHDIR;

   p->fsFlag = fsFlag;

   if (fsFlag == CD_EXPLICIT || fsFlag == CD_VERIFY) {
      p->vpfsd = *queryVPFSD(pcdfsi->cdi_hVPB);
      p->cdfsi = *pcdfsi;
      if (fsFlag == CD_EXPLICIT) {
         if (strlen(pszDir) >= CCHMAXPATH)
            RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
         strcpy(p->szDir, pszDir);
      }
   }

   p->cdfsd = *pcdfsd;
   p->iCurDirEnd = iCurDirEnd;

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   if (fsFlag == CD_EXPLICIT || fsFlag == CD_VERIFY)
      *pcdfsd = p->cdfsd;

   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_MKDIR(
   struct cdfsi far * pcdfsi,
   CDFSD far * pcdfsd,
   char far * pszName,
   unsigned short iCurDirEnd,
   PEAOP pEABuf,
   unsigned short flags
   )
{
   int rc;
   struct mkdir far * p = &pRequest->data.mkdir;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_MKDIR;

   p->vpfsd = *queryVPFSD(pcdfsi->cdi_hVPB);
   p->cdfsi = *pcdfsi;
   p->cdfsd = *pcdfsd;

   if (strlen(pszName) >= CCHMAXPATH)
      RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
   strcpy(p->szName, pszName);

   p->iCurDirEnd = iCurDirEnd;

   if (!IS_NULL(pEABuf)) {
      rc = copyEAOP(pEABuf, CEA_FEAS_TO_BUF, 0);
      if (rc) RELEASE_AND_EXIT(rc);
      p->fHasEAs = 1;
   }
   else p->fHasEAs = 0;

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   if (!IS_NULL(pEABuf)) {
      rc = copyEAOP(pEABuf, CEA_SET_OERROR, p->oError);
      if (rc) RELEASE_AND_EXIT(rc);
   }

   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_RMDIR(
   struct cdfsi far * pcdfsi,
   CDFSD far * pcdfsd,
   char far * pszName,
   unsigned short iCurDirEnd
   )
{
   int rc;
   struct rmdir far * p = &pRequest->data.rmdir;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_RMDIR;

   p->vpfsd = *queryVPFSD(pcdfsi->cdi_hVPB);
   p->cdfsi = *pcdfsi;
   p->cdfsd = *pcdfsd;

   if (strlen(pszName) >= CCHMAXPATH)
      RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
   strcpy(p->szName, pszName);

   p->iCurDirEnd = iCurDirEnd;

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   RELEASE_AND_EXIT(pRequest->rc);
}


/* If something goes wrong in the postprocessing of FS_FINDFIRST,
   we have to clean up the search resources in the daemon.  So
   we send a FINDCLOSE. */
APIRET undoFindFirst(struct cdfsi far * pcdfsi)
{
   FSFSD fsfsd = pRequest->data.findfirst.fsfsd;
   struct findclose far * p = &pRequest->data.findclose;
   pRequest->rq = FSRQ_FINDCLOSE;
   p->fsfsd = fsfsd;
   p->vpfsd = *queryVPFSD(pcdfsi->cdi_hVPB);
   return signalDaemonAndWait();
}


int IFSEXPORT
FS_FINDFIRST(
   struct cdfsi far * pcdfsi,
   CDFSD far * pcdfsd,
   char far * pszName,
   unsigned short iCurDirEnd,
   unsigned short fsAttr,
   struct fsfsi far * pfsfsi,
   FSFSD far * pfsfsd,
   char far * pData,
   unsigned short cbData,
   unsigned short far * pcMatch,
   unsigned short usLevel,
   unsigned short fsFlags
   )
{
   int rc, rc2;
   struct findfirst far * p = &pRequest->data.findfirst;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_FINDFIRST;

   p->vpfsd = *queryVPFSD(pcdfsi->cdi_hVPB);
   p->cdfsi = *pcdfsi;
   p->cdfsd = *pcdfsd;

   if (strlen(pszName) >= CCHMAXPATH)
      RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
   strcpy(p->szName, pszName);
   p->iCurDirEnd = iCurDirEnd;

   p->fsAttr = fsAttr;
   p->cbData = cbData;
   p->cMatch = *pcMatch;
   p->usLevel = usLevel;
   p->fsFlags = fsFlags;

   if (usLevel == FIL_QUERYEASFROMLIST) {
      rc = copyEAOP((PEAOP) pData, CEA_GEAS_TO_BUF, 0);
      if (rc) return rc;
      p->cbData -= sizeof(EAOP);
   }

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   if (!pRequest->rc || pRequest->rc == ERROR_EAS_DIDNT_FIT) {
      rc = FSH_PROBEBUF(PB_OPWRITE, pData, cbData);
      if (rc) {
         rc2 = undoFindFirst(pcdfsi);
         if (rc2) RELEASE_AND_EXIT(rc2);
         RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
      }
      if (usLevel == FIL_QUERYEASFROMLIST) {
         rc = copyEAOP((PEAOP) pData, CEA_SET_OERROR, p->oError);
         if (rc) {
            rc2 = undoFindFirst(pcdfsi);
            if (rc2) RELEASE_AND_EXIT(rc2);
            RELEASE_AND_EXIT(rc);
         }
         pData += sizeof(EAOP);
         cbData -= sizeof(EAOP);
      }
      memcpy(pData, pFSData, cbData);
   }

   *pfsfsd = p->fsfsd;
   *pcMatch = p->cMatch;
      
   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_FINDNEXT(
   struct fsfsi far * pfsfsi,
   FSFSD far * pfsfsd,
   char far * pData,
   unsigned short cbData,
   unsigned short far * pcMatch,
   unsigned short usLevel,
   unsigned short fsFlags
   )
{
   int rc;
   struct findnext far * p = &pRequest->data.findnext;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_FINDNEXT;

   p->vpfsd = *queryVPFSD(pfsfsi->fsi_hVPB);
   p->fsfsd = *pfsfsd;
   p->cbData = cbData;
   p->cMatch = *pcMatch;
   p->usLevel = usLevel;
   p->fsFlags = fsFlags;

   if (usLevel == FIL_QUERYEASFROMLIST) {
      rc = copyEAOP((PEAOP) pData, CEA_GEAS_TO_BUF, 0);
      if (rc) return rc;
      p->cbData -= sizeof(EAOP);
   }

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   if (!pRequest->rc || pRequest->rc == ERROR_EAS_DIDNT_FIT) {
      rc = FSH_PROBEBUF(PB_OPWRITE, pData, cbData);
      if (rc) RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
      if (usLevel == FIL_QUERYEASFROMLIST) {
         rc = copyEAOP((PEAOP) pData, CEA_SET_OERROR, p->oError);
         if (rc) RELEASE_AND_EXIT(rc);
         pData += sizeof(EAOP);
         cbData -= sizeof(EAOP);
      }
      memcpy(pData, pFSData, cbData);
   }

   *pcMatch = p->cMatch;

   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_FINDFROMNAME(
   struct fsfsi far * pfsfsi,
   FSFSD far * pfsfsd,
   char far * pData,
   unsigned short cbData,
   unsigned short far * pcMatch,
   unsigned short usLevel,
   unsigned long ulPosition,
   char far * pszName,
   unsigned short fsFlags
   )
{
   int rc;
   struct findfromname far * p = &pRequest->data.findfromname;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_FINDFROMNAME;

   p->vpfsd = *queryVPFSD(pfsfsi->fsi_hVPB);
   p->fsfsd = *pfsfsd;
   p->cbData = cbData;
   p->cMatch = *pcMatch;
   p->usLevel = usLevel;
   p->fsFlags = fsFlags;
   p->ulPosition = ulPosition;

   if (strlen(pszName) >= CCHMAXPATH)
      RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
   strcpy(p->szName, pszName);

   if (usLevel == FIL_QUERYEASFROMLIST) {
      rc = copyEAOP((PEAOP) pData, CEA_GEAS_TO_BUF, 0);
      if (rc) return rc;
      p->cbData -= sizeof(EAOP);
   }

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   if (!pRequest->rc || pRequest->rc == ERROR_EAS_DIDNT_FIT) {
      rc = FSH_PROBEBUF(PB_OPWRITE, pData, cbData);
      if (rc) RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
      if (usLevel == FIL_QUERYEASFROMLIST) {
         rc = copyEAOP((PEAOP) pData, CEA_SET_OERROR, p->oError);
         if (rc) RELEASE_AND_EXIT(rc);
         pData += sizeof(EAOP);
         cbData -= sizeof(EAOP);
      }
      memcpy(pData, pFSData, cbData);
   }

   *pcMatch = p->cMatch;

   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_FINDCLOSE(
   struct fsfsi far * pfsfsi,
   FSFSD far * pfsfsd
   )
{
   int rc;
   struct findclose far * p = &pRequest->data.findclose;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_FINDCLOSE;

   p->vpfsd = *queryVPFSD(pfsfsi->fsi_hVPB);
   p->fsfsd = *pfsfsd;

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_FINDNOTIFYFIRST(
   struct cdfsi far * pcdfsi,
   CDFSD far * pcdfsd,
   char far * pName,
   unsigned short iCurDirEnd,
   unsigned short attr,
   unsigned short far * pHandle,
   char far * pData,
   unsigned short cbData,
   unsigned short far * pcMatch,
   unsigned short level,
   unsigned long timeout
   )
{
   int rc;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_FINDNOTIFYFIRST;

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_FINDNOTIFYNEXT(
   unsigned short handle,
   char far * pData,
   unsigned short cbData,
   unsigned short far * pcMatch,
   unsigned short infolevel,
   unsigned long timeout
   )
{
   int rc;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_FINDNOTIFYNEXT;

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_FINDNOTIFYCLOSE(
   unsigned short handle
   )
{
   int rc;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_FINDNOTIFYCLOSE;

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   RELEASE_AND_EXIT(pRequest->rc);
}


int IFSEXPORT
FS_PROCESSNAME(
   char far * pszName
   )
{
#if 0
   int rc;
   struct processname far * p = &pRequest->data.processname;

   if (rc = requestExchangeXS()) return rc;

   pRequest->rq = FSRQ_PROCESSNAME;

   if (strlen(pszName) >= CCHMAXPATH)
      RELEASE_AND_EXIT(ERROR_INVALID_PARAMETER);
   strcpy(p->szName, pszName);

   if (rc = signalDaemonAndWait()) RELEASE_AND_EXIT(rc);

   strcpy(pszName, p->szName);

   RELEASE_AND_EXIT(pRequest->rc);
#endif
   return NO_ERROR;
}


int IFSEXPORT
FS_NMPIPE(
   struct sffsi far * psffsi,
   SFFSD far * psffsd,
   unsigned short OpType,
   union npoper far * pOpRec,
   char far * pData,
   char far * pName
   )
{
   /* We don't do remote named pipe stuff. */
   return ERROR_NOT_SUPPORTED;
}


int IFSEXPORT
FS_SETSWAP(
   struct sffsi far * psffsi,
   SFFSD far * psffsd
   )
{
   /* We don't support the swap file. */
   return ERROR_NOT_SUPPORTED;
}
