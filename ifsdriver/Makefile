BASE = ..
include $(BASE)/Makefile.incl

MANIFEST := Makefile \
 fsd.h stubfsd.c stubfsd.def stubfsd.h

ifeq ($(SYSTEM), os2)

DDK_H = d:\\programming\\ddk\\base
IFS_H = d:\\programming\\headers\\ifs

#CC16 = cl
CC16 = wcc
LINK16 = link

# /c    = compile?
# /W3   = warning level
# /Zp   = pack on ?
# /G2s  = 286 / no stack checking
# /Anlw = ? large /
# /Onir = disable unsafe / enable intrinsics / disable inline return
#C16FLAGS = /c /W3 /Zp /G2s /Anlw /Onir # /Fc # /Od

# /bd = build DLL
# /wx = warnings
# /oi = expand intrinsics
# /3  = optimize for 386
# /ml = large memory model
# /zu = SS != DGROUP
# /s  = remove stack overflow checks
# /r  = save segment registers across calls
C16FLAGS = /bd /wx /oi /3 /ml /zu /s /r

L16FLAGS = /map /nod /exepack /packd /a:16 /far

#C16INC = -I$(DDK_H)/h -I$(IFS_H)
C16INC = /i=$(DDK_H)\\h /i=$(IFS_H) /i=$(WATCOM)\\h

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