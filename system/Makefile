BASE = ..
include $(BASE)/Makefile.incl

SUBDIRS := os2 posix

MANIFEST := Makefile sysdep.h types.h

all clean clean-stuff install depend:
	for subdir in $(SUBDIRS); do \
	  (cd $$subdir && $(MAKE) -w $@) || exit 1; \
	done
