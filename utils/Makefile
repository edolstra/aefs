BASE = ..
include $(BASE)/Makefile.incl

PROGS = mkaefs.c aefsck.c aefsdump.c
# testcipher.c # cp2aefs.c dumpaefs.c 

SRCS = $(PROGS) utilutils.c

LIB = utilutils.o $(BASE)/misc/getopt.a \
 $(BASE)/corefs/corefs.a $(BASE)/ciphers/ciphers.a \
 $(BASE)/system/$(SYSTEM)/sysdep.a 

all: $(PROGS:.c=$(EXE))

$(PROGS:.c=$(EXE)): $(LIB) 

%$(EXE): %.o 
	$(CC) $(CFLAGS) $(LDFLAGS) $< $(LIB) $(SYSLIB) -o $@

TIMES = 1000000 # blocks (= 16 MB for 128 bit ciphers)

timings: testcipher$(EXE) 
	-rm -f $@
	testcipher$(EXE) t none $(TIMES) >>$@
	testcipher$(EXE) t twofish-128 $(TIMES) >>$@
	testcipher$(EXE) t twofish_ref-128 $(TIMES) >>$@
	testcipher$(EXE) t rijndael-128 $(TIMES) >>$@

# Check the ciphers against a few test vectors that are known
# to be correct.
check: checkvectors.pl testcipher$(EXE) testvec
	checkvectors.pl < testvec

clean-extra:
	$(RM) $(PROGS:.c=$(EXE))

install: all
	$(CP) $(PROGS:.c=$(EXE)) $(INSTALLDIR)

ifneq ($(MAKECMDGOALS),clean)
include $(SRCS:.c=.d)
endif
