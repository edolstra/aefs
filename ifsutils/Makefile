BASE = ..
include $(BASE)/Makefile.incl

MANIFEST := Makefile \
 aefsparm.c mntaefs.c umntaefs.c

ifeq ($(SYSTEM), os2)

PROGS = mntaefs.c umntaefs.c aefsparm.c

LIBS = $(BASE)/misc/getopt.a $(BASE)/utils/utilutils.o

all: $(PROGS:.c=$(EXE))

$(PROGS:.c=$(EXE)): $(LIBS)

%$(EXE): %.o 
	$(CC) $(CFLAGS) $(LDFLAGS) $< $(LIBS) $(SYSLIBS) -o $@

clean-extra:
	$(RM) $(PROGS:.c=$(EXE))

install: all
	$(CP) $(PROGS:.c=$(EXE)) $(INSTALLDIR)

ifneq ($(MAKECMDGOALS),clean)
include $(PROGS:.c=.d)
endif

endif