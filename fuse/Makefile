BASE = ..
include $(BASE)/Makefile.incl

MANIFEST := Makefile aefsfuse.c 

ifeq ($(BUILD_FUSE), 1)

PROG = aefsfuse$(EXE)

all: $(PROG)

SRCS = aefsfuse.c

LIBS = $(BASE)/corefs/corefs.a $(BASE)/ciphers/ciphers.a \
 $(BASE)/system/$(SYSTEM)/sysdep.a $(BASE)/misc/misc.a \
 $(BASE)/utils/utilutils.o

SYSLIBS += -lfuse -lpthread

$(PROG): $(SRCS:.c=.o) $(LIBS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SRCS:.c=.o) $(LIBS) $(SYSLIBS) -o $@

clean-extra:
	$(RM) $(PROG)

install: all
	$(INSTALL_DIR) $(bindir)
	$(INSTALL_PROGRAM) $(PROG) $(bindir)

ifneq ($(MAKECMDGOALS),clean)
include $(SRCS:.c=.d)
endif

endif