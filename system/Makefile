BASE = ..
include $(BASE)/Makefile.incl

SUBDIRS := os2 posix

MANIFEST := Makefile sysdep.h types.h

all clean clean-stuff install depend:
	cd $(SYSTEM) && $(MAKE) -w $@