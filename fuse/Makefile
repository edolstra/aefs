BASE = ..
include $(BASE)/Makefile.incl

MANIFEST := Makefile

ifeq ($(BUILD_FUSE), 1)

PROG1 = aefsfuse$(EXE)
PROG2 = mntaefsfuse$(EXE)

all: $(PROG1) $(PROG2)

SRCS1 = aefsfuse.c loop.c
SRCS2 = mntaefsfuse.c
SRCS = $(SRCS1) $(SRCS2)

LIBS = $(BASE)/corefs/corefs.a $(BASE)/ciphers/ciphers.a \
 $(BASE)/system/$(SYSTEM)/sysdep.a $(BASE)/misc/misc.a \
 $(BASE)/utils/utilutils.o

$(PROG1): $(SRCS1:.c=.o) $(LIBS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SRCS1:.c=.o) $(LIBS) $(SYSLIBS) -o $@

$(PROG2): $(SRCS2:.c=.o) $(LIBS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SRCS2:.c=.o) $(LIBS) $(SYSLIBS) -o $@

clean-extra:
	$(RM) $(PROG1) $(PROG2)

install: all
	$(INSTALL_DIR) $(bindir)
	$(INSTALL_PROGRAM) $(PROG1) $(bindir)
	$(INSTALL_PROGRAM) $(PROG2) $(bindir)

ifneq ($(MAKECMDGOALS),clean)
include $(SRCS:.c=.d)
endif

endif