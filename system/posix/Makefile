BASE = ../..
include $(BASE)/Makefile.incl

MANIFEST := Makefile posix.c sysspec.h

SRCS = posix.c

ifeq ($(SYSTEM), posix)

all: sysdep.a 

sysdep.a: $(SRCS:.c=.o)
	ar crs $@ $?

ifneq ($(MAKECMDGOALS),clean)
include $(SRCS:.c=.d)
endif

endif

