BASE = .
include $(BASE)/Makefile.incl

SUBDIRS := \
 misc system ciphers corefs utils nfsd \
 ifsdriver ifsdaemon ifsutils

MANIFEST := COPYING Makefile Makefile.incl Makefile.conf.in \
 PGPKEY config.h.in config.sub config.guess \
 configure configure.in install-sh readme.src

all clean clean-stuff install depend:
	for subdir in $(SUBDIRS); do \
	  (cd $$subdir && $(MAKE) -w $@) || exit 1; \
	done

ifeq ($(SYSTEM), os2)
all: docs

docs: readme.txt readme.inf # readme.html

readme.txt: readme.src
	emxdoc -T -o $@ $<

readme.html: readme.src
	emxdoc -H -o $@ $<

readme.inf: readme.src
	emxdoc -I -o readme.ipf $<
	ipfc readme.ipf $@
	rm readme.ipf
endif

CHECKSUMS:
	md5sum -b `find . -type f` | pgp -staf +clearsig > $@

os2dist: all dist
	cp -p Makefile.conf $(distdir)
	cp -p config.h $(distdir)
	cp -p readme.txt $(distdir)
	cp -p readme.inf $(distdir)
	mkdir $(distdir)/bin
	cp -p utils/mkaefs.exe $(distdir)/bin
	cp -p utils/aefsck.exe $(distdir)/bin
	cp -p utils/aefsdump.exe $(distdir)/bin
	cp -p utils/aefsutil.exe $(distdir)/bin
	cp -p ifsdriver/stubfsd.ifs $(distdir)/bin
	cp -p ifsdaemon/aefsdmn.exe $(distdir)/bin
	cp -p ifsutils/mntaefs.exe $(distdir)/bin
	cp -p ifsutils/umntaefs.exe $(distdir)/bin
	cp -p ifsutils/aefsparm.exe $(distdir)/bin
#	cp -p nfsd/aefsnfsd.exe $(distdir)/bin
#	cp -p nfsd/aefsadd.exe $(distdir)/bin
	for i in $(distdir)/bin/*.exe; do emxbind -s $$i; done
	cd $(distdir) ; make CHECKSUMS
