BASE = ..
include $(BASE)/Makefile.incl

MANIFEST := Makefile \
 cipher.c cipher.h ciphertable.c ciphertable.h \
 identity.c identity.h rijndael.c rijndael.h \
 sha.c sha.h twofish.c twofish.h

SRCS = cipher.c ciphertable.c identity.c \
 twofish.c rijndael.c sha.c # twofish2.c 

all: ciphers.a

ciphers.a: $(SRCS:.c=.o)
	ar crs $@ $?

ifneq ($(MAKECMDGOALS),clean)
include $(SRCS:.c=.d)
endif
