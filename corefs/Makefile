BASE = ..
include $(BASE)/Makefile.incl

SRCS = sector.c storage.c infosector.c basefile.c \
 directory.c ea.c coreutils.c superblock.c

all: corefs.a 

corefs.a: $(SRCS:.c=.o)
	ar crs $@ $?

ifneq ($(MAKECMDGOALS),clean)
include $(SRCS:.c=.d)
endif
