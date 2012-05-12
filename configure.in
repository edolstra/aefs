dnl configure.in   -*-shell-script-*-
dnl Process this file with autoconf to produce a configure script. 

AC_INIT(Makefile.conf.in)
AC_CONFIG_HEADER(config.h)

AC_CANONICAL_SYSTEM

AC_PROG_CC
AC_PROG_INSTALL
AC_CHECK_PROG(CP,cp,cp -v)
AC_CHECK_PROG(RM,rm,rm -vf)

AC_CHECK_FUNCS(snprintf)
AC_CHECK_FUNCS(strcasecmp)
AC_CHECK_FUNCS(stricmp)
AC_CHECK_FUNCS(daemon)
AC_CHECK_FUNCS(setfsuid)
AC_CHECK_FUNCS(mlockall)
AC_CHECK_FUNCS(chown)

AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(xdr_void, nsl rpc)
AC_SEARCH_LIBS(syslog, syslog)


CPPFLAGS="-D_FILE_OFFSET_BITS=64 $CPPFLAGS"
AC_ARG_WITH(fuse, AC_HELP_STRING([--with-fuse=PATH],
  [prefix of the FUSE package]), CPPFLAGS="-I$withval/include $CPPFLAGS"; LDFLAGS="-L$withval/lib $LDFLAGS")
AC_CHECK_HEADER(fuse/fuse.h, BUILD_FUSE=1, BUILD_FUSE=0)
AC_SUBST(BUILD_FUSE)
if test "$BUILD_FUSE" = 0; then
    AC_MSG_WARN([the FUSE server will not be built])
fi


AC_CHECK_PROG(RPCGEN, rpcgen, rpcgen, false)

if test "$RPCGEN" = false; then
    BUILD_NFSD=0
    AC_MSG_WARN([the NFS server will not be built])
else    
    BUILD_NFSD=1
fi
AC_SUBST(BUILD_NFSD)


AC_C_INLINE

AC_C_BIGENDIAN
AC_CHECK_SIZEOF(int, 4)
AC_CHECK_SIZEOF(long, 4)


case $build_os in
os2_emx)
        SYSTEM=os2
        SHELL=sh.exe
        SYSCFLAGS=-Zmt
        SYSLDFLAGS=-Zcrtdll
        SYSLIBS="-lbsd -lgcc"
        EXEEXT=.exe
        ;;
*)
        SYSTEM=posix
        ;;
esac        
AC_SUBST(SYSTEM)
AC_SUBST(SHELL)
AC_SUBST(SYSINCL)
AC_SUBST(SYSCFLAGS)
AC_SUBST(SYSLDFLAGS)
AC_SUBST(SYSLIBS)

case $build_cpu in
*)
        OPTFLAGS="-O3"
        ;;
esac                
AC_SUBST(OPTFLAGS)

AC_SUBST(SHELL)

AC_OUTPUT(Makefile.conf)
