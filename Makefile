BASE = .
include $(BASE)/Makefile.incl

SUBDIRS = misc system/$(SYSTEM) ciphers corefs \
 utils ifsdriver ifsdaemon ifsutils

all clean clean-stuff install:
	for subdir in $(SUBDIRS); do \
	  (cd $$subdir && $(MAKE) -w $@) || exit 1; \
	done

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

CHECKSUMS:
	md5sum -b `find . -type f` | pgp -staf +clearsig > $@

dist: all install
	rm -rf $(TMPDIR)/aefs
	mkdir $(TMPDIR)/aefs
	cp -pr . $(TMPDIR)/aefs
	cd $(TMPDIR)/aefs ; make clean ; make CHECKSUMS
	cd $(TMPDIR) ; rm aefs.zip ; zip -9r aefs.zip aefs