BASE = ..
include $(BASE)/Makefile.incl

MANIFEST := Makefile \
 basefile.c corefs.h coreutils.c coreutils.h \
 directory.c ea.c infosector.c sector.c storage.c \
 superblock.c superblock.h

SRCS = sector.c storage.c infosector.c basefile.c \
 directory.c ea.c coreutils.c superblock.c

all: corefs.a 

corefs.a: $(SRCS:.c=.o)
	ar crs $@ $?

ifneq ($(MAKECMDGOALS),clean)
include $(SRCS:.c=.d)
endif
