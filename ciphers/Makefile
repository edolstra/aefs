BASE = ..
include $(BASE)/Makefile.incl

SRCS = cipher.c ciphertable.c identity.c \
 twofish.c rijndael.c sha.c # twofish2.c 

all: ciphers.a

ciphers.a: $(SRCS:.c=.o)
	ar crs $@ $?

ifneq ($(MAKECMDGOALS),clean)
include $(SRCS:.c=.d)
endif
