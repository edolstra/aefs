/* stubfsd.h -- Defines the interface between the ring 0 and ring 3
   components of an FSD.
   Copyright (C) 1999, 2001 Eelco Dolstra (eelco@cs.uu.nl).

   $Id: stubfsd.h,v 1.5 2001/09/23 13:30:15 eelco Exp $

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

#ifndef _STUBFSD_H
#define _STUBFSD_H

#include "fsd.h"


#pragma pack(4) /* GCC and MS-C must align structures identically */


/* FSCTL_STUBFSD_DAEMON_STARTED announces the daemon to the IFS.  pParm
   (input) points to a SET_EXCHANGE_BUFFERS structure. */
#define FSCTL_STUBFSD_DAEMON_STARTED 0x8000

/* FSCTL_STUBFSD_DAEMON_STOPPED tells the IFS that the daemon is
   terminating gracefully.  Can only be issued by the process that did
   the FSCTL_STUBFSD_DAEMON_STARTED FSCTL. */
#define FSCTL_STUBFSD_DAEMON_STOPPED 0x8001

/* FSCTL_STUBFSD_GET_REQUEST is used to retrieve the next request.  This
   FSCTL blocks in kernel mode until a request is available, or a
   signal (such as a break or kill) is received.  The request data is
   placed in the exchange buffers. */
#define FSCTL_STUBFSD_GET_REQUEST    0x8002

/* FSCTL_STUBFSD_DONE_REQUEST tells the IFS that the daemon has finished
   the current request.  The IFS will unblock the thread that is
   waiting for this request to finish. */
#define FSCTL_STUBFSD_DONE_REQUEST   0x8003

/* FSCTL_STUBFSD_RESET resets the IFS.  Debugging only. */
#define FSCTL_STUBFSD_RESET          0x8004


/* Errors. */
#define ERROR_STUBFSD_BASE               9000
#define ERROR_STUBFSD_DAEMON_NOT_RUNNING (ERROR_STUBFSD_BASE + 0)
#define ERROR_STUBFSD_DAEMON_RUNNING     (ERROR_STUBFSD_BASE + 1)
#define ERROR_STUBFSD_NOT_DAEMON         (ERROR_STUBFSD_BASE + 2)
#define ERROR_STUBFSD_INIT_FAILED        (ERROR_STUBFSD_BASE + 3)
#define ERROR_STUBFSD_DEADLOCK           (ERROR_STUBFSD_BASE + 4)
#define ERROR_STUBFSD_CALLER_INTERRUPTED (ERROR_STUBFSD_BASE + 5)


/* Request codes. */
#define FSRQ_FSCTL                 1
#define FSRQ_ATTACH                2
#define FSRQ_IOCTL                 3
#define FSRQ_FSINFO                4
#define FSRQ_FLUSHBUF              5
#define FSRQ_SHUTDOWN              6
#define FSRQ_OPENCREATE            7
#define FSRQ_CLOSE                 8
#define FSRQ_READ                  9
#define FSRQ_WRITE                10
#define FSRQ_CHGFILEPTR           11
#define FSRQ_NEWSIZE              12
#define FSRQ_FILEATTRIBUTE        13
#define FSRQ_FILEINFO             14
#define FSRQ_COMMIT               17
#define FSRQ_PATHINFO             18
#define FSRQ_DELETE               19
#define FSRQ_COPY                 20
#define FSRQ_MOVE                 21
#define FSRQ_CHDIR                22
#define FSRQ_MKDIR                23
#define FSRQ_RMDIR                24
#define FSRQ_FINDFIRST            25
#define FSRQ_FINDNEXT             26
#define FSRQ_FINDFROMNAME         27
#define FSRQ_FINDCLOSE            28
#define FSRQ_FINDNOTIFYFIRST      29
#define FSRQ_FINDNOTIFYNEXT       30
#define FSRQ_FINDNOTIFYCLOSE      31
#define FSRQ_PROCESSNAME          32


/* Make sure that:
     sizeof(VPFSD) <= 36
     sizeof(CDFSD) <= 8
     sizeof(SFFSD) <= 30
     sizeof(FSFSD) <= 24
*/
typedef struct { ULONG data[1]; } VPFSD;
typedef struct { ULONG data[2]; } CDFSD;
typedef struct { ULONG data[2]; } SFFSD;
typedef struct { ULONG data[1]; } FSFSD;


#ifndef RING0
#define far
#endif


#define FSXCHG_ATTACH_DEVMAX         8


typedef struct _FSREQUEST {
      ULONG rq;
      APIRET rc;
      union {

            struct fsctl {
                  USHORT iArgType;
                  USHORT usFunc;
                  USHORT cbParm;
                  USHORT cbMaxData;
                  USHORT cbData; /* result */
            } fsctl;
            
            struct attach {
                  USHORT fsFlag;
                  CHAR szDev[FSXCHG_ATTACH_DEVMAX];
                  CDFSD cdfsd;
                  USHORT cbParm;
                  VPFSD vpfsd; /* result */
            } attach;

            struct ioctl {
                  VPFSD vpfsd;
                  struct sffsi sffsi;
                  SFFSD sffsd;
                  USHORT usCat;
                  USHORT usFunc;
                  USHORT cbParm;
                  USHORT cbMaxData;
                  USHORT cbData; /* result */
            } ioctl;
            
            struct fsinfo {
                  VPFSD vpfsd;
                  USHORT fsFlag;
                  USHORT cbData;
                  USHORT usLevel;
            } fsinfo;

            struct flushbuf {
                  VPFSD vpfsd;
                  USHORT fsFlag;
            } flushbuf;

            struct shutdown {
                  USHORT usType;
            } shutdown;

            struct opencreate {
                  VPFSD vpfsd;
                  struct cdfsi cdfsi;
                  CDFSD cdfsd;
                  CHAR szName[CCHMAXPATH];
                  USHORT iCurDirEnd;
                  struct sffsi sffsi;
                  SFFSD sffsd;
                  ULONG flOpenMode;
                  USHORT fsOpenFlag;
                  USHORT usAction; /* result */
                  USHORT fsAttr;
                  USHORT fHasEAs;
                  USHORT oError; /* result */
                  USHORT fsGenFlag; /* result */
            } opencreate;

            struct close {
                  VPFSD vpfsd;
                  USHORT usType;
                  USHORT fsIOFlag;
                  struct sffsi sffsi;
                  SFFSD sffsd;
            } close;

            struct read {
                  VPFSD vpfsd;
                  struct sffsi sffsi;
                  SFFSD sffsd;
                  USHORT cbLen;
                  USHORT fsIOFlag;
            } read;

            struct write {
                  VPFSD vpfsd;
                  struct sffsi sffsi;
                  SFFSD sffsd;
                  USHORT cbLen;
                  USHORT fsIOFlag;
            } write;

            struct chgfileptr {
                  VPFSD vpfsd;
                  struct sffsi sffsi;
                  SFFSD sffsd;
                  LONG ibOffset;
                  USHORT usType;
                  USHORT fsIOFlag;
            } chgfileptr;

            struct newsize {
                  VPFSD vpfsd;
                  struct sffsi sffsi;
                  SFFSD sffsd;
                  ULONG cbLen;
                  USHORT fsIOFlag;
            } newsize;

            struct fileattribute {
                  VPFSD vpfsd;
                  USHORT fsFlag;
                  struct cdfsi cdfsi;
                  CDFSD cdfsd;
                  CHAR szName[CCHMAXPATH];
                  USHORT iCurDirEnd;
                  USHORT fsAttr;
            } fileattribute;

            struct fileinfo {
                  VPFSD vpfsd;
                  struct sffsi sffsi;
                  SFFSD sffsd;
                  USHORT usLevel;
                  USHORT cbData;
                  USHORT fsFlag;
                  USHORT fsIOFlag;
                  USHORT oError; /* result */
            } fileinfo;

            struct commit {
                  VPFSD vpfsd;
                  struct sffsi sffsi;
                  SFFSD sffsd;
                  USHORT usType;
                  USHORT fsIOFlag;
            } commit;

            struct pathinfo {
                  VPFSD vpfsd;
                  USHORT fsFlag;
                  struct cdfsi cdfsi;
                  CDFSD cdfsd;
                  CHAR szName[CCHMAXPATH];
                  USHORT iCurDirEnd;
                  USHORT usLevel;
                  USHORT cbData;
                  USHORT oError; /* result */
            } pathinfo;

            struct delete {
                  VPFSD vpfsd;
                  struct cdfsi cdfsi;
                  CDFSD cdfsd;
                  CHAR szName[CCHMAXPATH];
                  USHORT iCurDirEnd;
            } delete;

            struct move {
                  VPFSD vpfsd;
                  struct cdfsi cdfsi;
                  CDFSD cdfsd;
                  CHAR szSrc[CCHMAXPATH];
                  USHORT iSrcCurDirEnd;
                  CHAR szDst[CCHMAXPATH];
                  USHORT iDstCurDirEnd;
            } move;

            struct chdir {
                  VPFSD vpfsd;
                  USHORT fsFlag;
                  struct cdfsi cdfsi;
                  CDFSD cdfsd;
                  CHAR szDir[CCHMAXPATH];
                  USHORT iCurDirEnd;
            } chdir;

            struct mkdir {
                  VPFSD vpfsd;
                  struct cdfsi cdfsi;
                  CDFSD cdfsd;
                  CHAR szName[CCHMAXPATH];
                  USHORT iCurDirEnd;
                  USHORT fsFlags;
                  USHORT fHasEAs;
                  USHORT oError; /* result */
            } mkdir;

            struct rmdir {
                  VPFSD vpfsd;
                  struct cdfsi cdfsi;
                  CDFSD cdfsd;
                  CHAR szName[CCHMAXPATH];
                  USHORT iCurDirEnd;
            } rmdir;

            struct findfirst {
                  VPFSD vpfsd;
                  struct cdfsi cdfsi;
                  CDFSD cdfsd;
                  CHAR szName[CCHMAXPATH];
                  USHORT iCurDirEnd;
                  USHORT fsAttr;
                  FSFSD fsfsd;
                  USHORT cbData;
                  USHORT cMatch;
                  USHORT usLevel;
                  USHORT fsFlags;
                  USHORT oError; /* result */
            } findfirst;
            
            struct findnext {
                  VPFSD vpfsd;
                  FSFSD fsfsd;
                  USHORT cbData;
                  USHORT cMatch;
                  USHORT usLevel;
                  USHORT fsFlags;
                  USHORT oError; /* result */
            } findnext;
            
            struct findfromname {
                  VPFSD vpfsd;
                  FSFSD fsfsd;
                  USHORT cbData;
                  USHORT cMatch;
                  USHORT usLevel;
                  USHORT fsFlags;
                  ULONG ulPosition;
                  CHAR szName[CCHMAXPATH];
                  USHORT oError; /* result */
            } findfromname;
            
            struct findclose {
                  VPFSD vpfsd;
                  FSFSD fsfsd;
            } findclose;
            
            struct processname {
                  CHAR szName[CCHMAXPATH];
            } processname;
            
      } data;
} FSREQUEST;

typedef FSREQUEST far * PFSREQUEST;


typedef char FSDATA[65536];

typedef FSDATA far * PFSDATA;


/* Structure for FSCTL_STUBFSD_DAEMON_STARTED. */
typedef struct {
      /* Note that these are pointers into the linear address space of
         the daemon process. */
#ifdef RING0
      LIN        linRequest;
      LIN        linData;
#else
      PFSREQUEST pRequest;
      PFSDATA    pData;
#endif
} SETXCHGBUFFERS, far * PSETXCHGBUFFERS;


#pragma pack() /* back to default */


#endif /* !_STUBFSD_H */
