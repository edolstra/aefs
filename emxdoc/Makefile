BASE = ..
include $(BASE)/Makefile.incl

MANIFEST := Makefile \
 emxdoc.c input.c cond.c html.c ipf.c latex.c text.c xref.c lb.c \
 emxdoc.h cond.h html.h ipf.h latex.h text.h xref.h lb.h

SRCS = emxdoc.c input.c cond.c html.c ipf.c latex.c text.c xref.c lb.c

all: emxdoc$(EXE)

emxdoc$(EXE): $(SRCS:.c=.o)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SRCS:.c=.o) $(LIBS) $(SYSLIBS) -o emxdoc$(EXE)

clean-extra:
	$(RM) emxdoc$(EXE) 

ifneq ($(MAKECMDGOALS),clean)
include $(SRCS:.c=.d)
endif
