BASE = ..
include $(BASE)/Makefile.incl

MANIFEST := Makefile \
 aefsfuse.c aefsfuse.h loop.c

ifeq ($(BUILD_FUSE), 1)

PROG = aefsfuse$(EXE)

all: $(PROG)

SRCS = aefsfuse.c loop.c

LIBS = $(BASE)/corefs/corefs.a $(BASE)/ciphers/ciphers.a \
 $(BASE)/system/$(SYSTEM)/sysdep.a $(BASE)/misc/misc.a \
 $(BASE)/utils/utilutils.o

SYSLIBS += -lfuse -lpthread

CFLAGS += -D_FILE_OFFSET_BITS=64

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