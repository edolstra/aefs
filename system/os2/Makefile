BASE = ../..
include $(BASE)/Makefile.incl

SRCS = os2.c

all: sysdep.a 

sysdep.a: $(SRCS:.c=.o)
	ar crs $@ $?

ifneq ($(MAKECMDGOALS),clean)
include $(SRCS:.c=.d)
endif
