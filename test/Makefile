BASE = ..
include $(BASE)/Makefile.incl

MANIFEST = Makefile \
 write.c

PROGS = write.c

SRCS = $(PROGS)

TESTVOL = ./testvol
TESTPW = foo

LIBS = \
 $(BASE)/corefs/corefs.a $(BASE)/ciphers/ciphers.a \
 $(BASE)/system/$(SYSTEM)/sysdep.a $(BASE)/misc/misc.a

CFLAGS += -DTESTVOL="\"$(TESTVOL)\"" -DTESTPW="\"$(TESTPW)\""

$(PROGS:.c=$(EXE)): $(LIBS) 

%$(EXE): %.o 
	$(CC) $(CFLAGS) $(LDFLAGS) $< $(LIBS) $(SYSLIBS) -o $@

clean-extra:
	$(RM) $(PROGS:.c=$(EXE)) testcipher$(EXE) 

check: check-write

check-write: write$(EXE)
	$(RM) -rf $(TESTVOL)
	../utils/mkaefs$(EXE) -k $(TESTPW) $(TESTVOL)
	./write$(EXE)

ifneq ($(MAKECMDGOALS),clean)
include $(SRCS:.c=.d)
endif
