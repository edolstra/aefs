BASE = ..
include $(BASE)/Makefile.incl

MANIFEST = Makefile \
 aefsck.c aefsck.h aefsdump.c aefsutil.c checkvectors.pl \
 mkaefs.c testcipher.c testvec \
 utilutils.c utilutils.h

PROGS = mkaefs.c aefsck.c aefsdump.c aefsutil.c
# testcipher.c # cp2aefs.c dumpaefs.c 

SRCS = $(PROGS) utilutils.c

LIBS = utilutils.o \
 $(BASE)/corefs/corefs.a $(BASE)/ciphers/ciphers.a \
 $(BASE)/system/$(SYSTEM)/sysdep.a $(BASE)/misc/misc.a

all: $(PROGS:.c=$(EXE))

$(PROGS:.c=$(EXE)): $(LIBS) 

%$(EXE): %.o 
	$(CC) $(CFLAGS) $(LDFLAGS) $< $(LIBS) $(SYSLIBS) -o $@

TIMES = 1000000 # blocks (= 16 MB for 128 bit ciphers)

timings: testcipher$(EXE) 
	-rm -f $@
	./testcipher$(EXE) t none $(TIMES) >>$@
	./testcipher$(EXE) t twofish-128 $(TIMES) >>$@
#	./testcipher$(EXE) t twofish_ref-128 $(TIMES) >>$@
	./testcipher$(EXE) t rijndael-128 $(TIMES) >>$@

testcipher$(EXE): testcipher.o

# Check the ciphers against a few test vectors that are known
# to be correct.
check: checkvectors.pl testcipher$(EXE) testvec
	perl checkvectors.pl < testvec

clean-extra:
	$(RM) $(PROGS:.c=$(EXE))

install: all
	$(INSTALL_DIR) $(bindir)
	$(INSTALL_PROGRAM) $(PROGS:.c=$(EXE)) $(bindir)

ifneq ($(MAKECMDGOALS),clean)
include $(SRCS:.c=.d)
endif
