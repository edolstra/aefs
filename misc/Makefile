BASE = ..
include $(BASE)/Makefile.incl

MANIFEST := Makefile getopt.c getopt.h getopt1.c

GETOPT = getopt.c getopt1.c
SRCS = $(GETOPT)

all: getopt.a

getopt.a: $(GETOPT:.c=.o)
	ar crs $@ $?

ifneq ($(MAKECMDGOALS),clean)
include $(SRCS:.c=.d)
endif
