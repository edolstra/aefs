BASE = ..
include $(BASE)/Makefile.incl

OPEN_FILES_LIMIT = 512

PROG = aefsnfsd$(EXE)

SRCS = aefsnfsd.c nfs_prot_svc.c nfs_prot_xdr.c mount_svc.c mount_xdr.c

LIB = $(BASE)/corefs/corefs.a $(BASE)/ciphers/ciphers.a \
 $(BASE)/misc/getopt.a \
 $(BASE)/system/$(SYSTEM)/sysdep.a

CFLAGS += -Wno-switch

SYSLIB += 

all: $(PROG)

$(PROG): $(SRCS:.c=.o) $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SRCS:.c=.o) $(LIB) $(SYSLIB) -o $@
#	emxbind -a $@ "-h$(OPEN_FILES_LIMIT)"

%.h: %.x
	rpcgen -h $^ > $@

%_xdr.c: %.x
	rpcgen -c $^ > $@

%_clnt.c: %.x
	rpcgen -l $^ > $@

%_svc.c: %.x
	rpcgen -m $^ > $@

clean-extra:
	$(RM) $(PROG)
	$(RM) nfs_prot.h nfs_prot_clnt.c nfs_prot_svc.c nfs_prot_xdr.c
	$(RM) mount.h mount_clnt.c mount_svc.c mount_xdr.c

install: all
	$(CP) $(PROG) $(INSTALLDIR)

ifneq ($(MAKECMDGOALS),clean)
include $(SRCS:.c=.d)
endif
