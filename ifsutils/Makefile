BASE = ..
include $(BASE)/Makefile.incl

PROGS = mntaefs.c umntaefs.c aefsparm.c

LIB = $(BASE)/misc/getopt.a $(BASE)/utils/utilutils.o

all: $(PROGS:.c=$(EXE))

$(PROGS:.c=$(EXE)): $(LIB)

%$(EXE): %.o 
	$(CC) $(CFLAGS) $(LDFLAGS) $< $(LIB) $(SYSLIB) -o $@

clean-extra:
	$(RM) $(PROGS:.c=$(EXE))

install: all
	$(CP) $(PROGS:.c=$(EXE)) $(INSTALLDIR)

ifneq ($(MAKECMDGOALS),clean)
include $(PROGS:.c=.d)
endif
