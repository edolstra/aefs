BASE = ..
include $(BASE)/Makefile.incl

MANIFEST := Makefile getopt.c getopt.h getopt1.c missing.c

SRCS = getopt.c getopt1.c missing.c

all: misc.a

misc.a: $(SRCS:.c=.o)
	ar crs $@ $?

ifneq ($(MAKECMDGOALS),clean)
include $(SRCS:.c=.d)
endif
