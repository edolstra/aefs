BASE = ..
include $(BASE)/Makefile.incl

MANIFEST := Makefile getopt.c getopt.h getopt1.c missing.c logging.c logging.h

SRCS = getopt.c getopt1.c missing.c logging.c

all: misc.a

misc.a: $(SRCS:.c=.o)
	ar crs $@ $?

ifneq ($(MAKECMDGOALS),clean)
include $(SRCS:.c=.d)
endif
