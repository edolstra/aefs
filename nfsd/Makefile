BASE = ..
include $(BASE)/Makefile.incl

MANIFEST := Makefile \
 aefsadd.c aefsctrl.x aefsnfsd.c mount.x nfs_prot.x

PROG1 = aefsnfsd$(EXE)
PROG2 = aefsadd$(EXE)

all: $(PROG1) $(PROG2)

SRCS1 = aefsnfsd.c \
 nfs_prot_svc.c nfs_prot_xdr.c \
 mount_svc.c mount_xdr.c \
 aefsctrl_svc.c aefsctrl_xdr.c
SRCS2 = aefsadd.c aefsctrl_clnt.c aefsctrl_xdr.c
SRCS = $(SRCS1) $(SRCS2)

LIB = $(BASE)/corefs/corefs.a $(BASE)/ciphers/ciphers.a \
 $(BASE)/misc/getopt.a \
 $(BASE)/system/$(SYSTEM)/sysdep.a

CFLAGS += -Wno-switch

$(PROG1): $(SRCS1:.c=.o) $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SRCS1:.c=.o) $(LIB) $(SYSLIB) -o $@

$(PROG2): $(SRCS2:.c=.o) $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SRCS2:.c=.o) \
         ../utils/utilutils.o $(LIB) $(SYSLIB) -o $@

clean-extra:
	$(RM) $(PROG1) $(PROG2)
	$(RM) nfs_prot.h nfs_prot_clnt.c nfs_prot_svc.c nfs_prot_xdr.c
	$(RM) mount.h mount_clnt.c mount_svc.c mount_xdr.c
	$(RM) aefsctrl.h aefsctrl_clnt.c aefsctrl_svc.c aefsctrl_xdr.c

install: all
	$(INSTALL_DIR) $(bindir)
	$(INSTALL_PROGRAM) $(PROG1) $(PROG2) $(bindir)

ifneq ($(MAKECMDGOALS),clean)
include $(SRCS:.c=.d)
endif
