BASE = ..
include $(BASE)/Makefile.incl

MANIFEST := Makefile \
 aefsdint.h aefsdmn.c aefsdmn.h attach.c dir.c ea.c \
 fileinfo.c fileio.c fileop.c find.c misc.c \
 openclose.c utils.c

ifeq ($(SYSTEM), os2)

OPEN_FILES_LIMIT = 512

CFLAGS += -DOPEN_FILES_LIMIT=$(OPEN_FILES_LIMIT)

SRCS = aefsdmn.c attach.c find.c misc.c dir.c openclose.c \
 fileio.c fileinfo.c fileop.c ea.c utils.c

LIBS = $(BASE)/corefs/corefs.a $(BASE)/ciphers/ciphers.a \
 $(BASE)/misc/misc.a \
 $(BASE)/system/$(SYSTEM)/sysdep.a

all: aefsdmn$(EXE)

aefsdmn$(EXE): $(SRCS:.c=.o) $(LIBS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SRCS:.c=.o) $(LIBS) $(SYSLIBS) -o $@
	emxbind -a $@ "-h$(OPEN_FILES_LIMIT)"

clean-extra:
	$(RM) aefsdmn$(EXE)

install: all
	$(INSTALL_DIR) $(bindir)
	$(INSTALL_PROGRAM) aefsdmn$(EXE) $(bindir)

ifneq ($(MAKECMDGOALS),clean)
include $(SRCS:.c=.d)
endif

endif