BASE = ..
include $(BASE)/Makefile.incl

MANIFEST := Makefile \
 fsd.h stubfsd.c stubfsd.def stubfsd.h

ifeq ($(SYSTEM), os2)

DDK    = d:/programming/ddk/base
MSC60  = d:/programming/ddk/msc60

CC16 = cl
LINK16 = link

C16FLAGS = /c /W3 /Zp /G2s /Anlw /Onir # /Fc # /Od
L16FLAGS = /map /nod /exepack /packd /a:16 /far

C16INC = -I$(DDK)/h \
 -Id:/programming/headers/ifs

L16LIBS = dhcalls.lib fshelper.lib

all: stubfsd.ifs

stubfsd.ifs: stubfsd.obj stubfsd.def 
	$(LINK16) $(L16FLAGS) stubfsd.obj,$@,,$(L16LIBS),stubfsd.def

stubfsd.obj: stubfsd.c fsd.h stubfsd.h
	$(CC16) $(C16FLAGS) $(C16INC) $<

clean-extra:
	$(RM) stubfsd.ifs *.cod *.obj *.map

install: all
	$(INSTALL_DIR) $(bindir)
	$(INSTALL_PROGRAM) stubfsd.ifs $(bindir)

endif