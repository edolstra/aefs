BASE = ..
include $(BASE)/Makefile.incl

OPEN_FILES_LIMIT = 512

CFLAGS += -DOPEN_FILES_LIMIT=$(OPEN_FILES_LIMIT)

SRCS = aefsdmn.c attach.c find.c misc.c dir.c openclose.c \
 fileio.c fileinfo.c fileop.c ea.c utils.c

LIB = $(BASE)/corefs/corefs.a $(BASE)/ciphers/ciphers.a \
 $(BASE)/misc/getopt.a \
 $(BASE)/system/$(SYSTEM)/sysdep.a

SYSLIB += -lsyslog -lsocket

all: aefsdmn$(EXE)

aefsdmn$(EXE): $(SRCS:.c=.o) $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SRCS:.c=.o) $(LIB) $(SYSLIB) -o $@
	emxbind -a $@ "-h$(OPEN_FILES_LIMIT)"

clean-extra:
	$(RM) aefsdmn$(EXE)

install: all
	$(CP) aefsdmn$(EXE) $(INSTALLDIR)

ifneq ($(MAKECMDGOALS),clean)
include $(SRCS:.c=.d)
endif
