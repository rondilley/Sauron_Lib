dnl Process this file with autoconf to produce a configure script
m4_include([m4/version.m4])
AC_PREREQ([2.59])
AC_INIT([Sauron], VERSION_NUMBER, [ron.dilley@uberadmin.com], [sauron], [http://www.uberadmin.com/Projects/sauron/])
AC_CONFIG_SRCDIR(src/sauron.c)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS

AM_INIT_AUTOMAKE
LT_INIT

dnl Checks for programs
AC_PROG_CC
AC_PROG_LIBTOOL

dnl make /usr/local as the default install dir
AC_PREFIX_DEFAULT(/usr/local)

CFLAGS="${CFLAGS} -I. -I.. -I../include"

dnl Check for pthreads (required for spinlocks)
AX_PTHREAD([
    LIBS="$PTHREAD_LIBS $LIBS"
    CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
    CC="$PTHREAD_CC"
], [
    AC_MSG_ERROR([pthreads is required])
])

DEBUG="no"
AC_ARG_ENABLE(debug,
    [  --enable-debug          Enable debugging],
    [ if test "$GCC" = yes; then
          DEBUG="yes"
          CFLAGS="${CFLAGS} -DDEBUG -ggdb"
      else
          DEBUG="yes"
          CFLAGS="${CFLAGS} -DDEBUG"
      fi
    ],)

MEM_DEBUG="no"
AC_ARG_ENABLE(memdebug,
    [  --enable-memdebug       Enable memory debugging],
      MEM_DEBUG="yes"
      CFLAGS="${CFLAGS} -DMEM_DEBUG"
    ,)

SHOW_MEM_DEBUG="no"
AC_ARG_ENABLE(showmemdebug,
    [  --enable-showmemdebug   Enable verbose memory debugging],
      SHOW_MEM_DEBUG="yes"
      MEM_DEBUG="yes"
      CFLAGS="${CFLAGS} -DMEM_DEBUG -DSHOW_MEM_DEBUG"
    ,)

HARDENING="yes"
AC_ARG_ENABLE(hardening,
    [  --enable-hardening      Enable compiler security hardening (default: yes)],
    [ HARDENING="$enableval" ],
    [ HARDENING="yes" ])

if test "$HARDENING" = "yes"; then
    if test "$GCC" = yes; then
        CFLAGS="${CFLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIC"
        CFLAGS="${CFLAGS} -Wformat -Wformat-security -Werror=format-security"
        CFLAGS="${CFLAGS} -fno-strict-overflow -fno-delete-null-pointer-checks"
        LDFLAGS="${LDFLAGS} -Wl,-z,relro -Wl,-z,now"
    fi
fi

STATIC_ANALYSIS="no"
AC_ARG_ENABLE(static-analysis,
    [  --enable-static-analysis Enable static analysis tools],
    [
          STATIC_ANALYSIS="yes"
          AC_CHECK_PROG(CLANG_ANALYZER, scan-build, yes, no)
          AC_CHECK_PROG(CPPCHECK, cppcheck, yes, no)

          if test "$CLANG_ANALYZER" = "yes"; then
            AC_MSG_NOTICE([Clang Static Analyzer (scan-build) found])
          fi

          if test "$CPPCHECK" = "yes"; then
            AC_MSG_NOTICE([cppcheck found])
          fi
    ],)

GPROF="no"
AC_ARG_ENABLE(gprof,
    [  --enable-gprof          Enable profiler],
    [ if test "$GCC" = yes; then
          GPROF="yes"
          CFLAGS="${CFLAGS} -DGPROF -pg"
          CFLAGS="${CFLAGS} -fno-omit-frame-pointer"
      else
          GPROF="yes"
          CFLAGS="${CFLAGS} -DGPROF"
      fi
    ],
    [ if test "$GCC" = yes; then
          CFLAGS="${CFLAGS} -fomit-frame-pointer"
      fi
    ])

dnl ############## VM Optimization: Adaptive Mutex
ADAPTIVE_MUTEX="no"
AC_ARG_ENABLE(adaptive-mutex,
    [  --enable-adaptive-mutex Use adaptive mutex instead of spinlocks (for VMs)],
    [
        ADAPTIVE_MUTEX="yes"
        AC_DEFINE([USE_ADAPTIVE_MUTEX], [1], [Use adaptive mutex instead of spinlock for VM compatibility])
    ],)

dnl ############## SIMD Optimization
SIMD_ENABLED="no"
AC_ARG_ENABLE(simd,
    [  --enable-simd           Enable SIMD optimizations (auto-detected if not specified)],
    [ENABLE_SIMD="$enableval"],
    [ENABLE_SIMD="auto"])

if test "$ENABLE_SIMD" != "no"; then
    AC_MSG_CHECKING([for AVX2 support])
    saved_CFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS -mavx2"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
        #include <immintrin.h>
    ]], [[
        __m256i a = _mm256_setzero_si256();
        __m256i b = _mm256_add_epi16(a, a);
        (void)b;
    ]])], [
        AC_MSG_RESULT([yes])
        AC_DEFINE([HAVE_AVX2], [1], [Define if AVX2 intrinsics are available])
        SIMD_ENABLED="yes"
    ], [
        AC_MSG_RESULT([no])
        CFLAGS="$saved_CFLAGS"
        if test "$ENABLE_SIMD" = "yes"; then
            AC_MSG_ERROR([SIMD requested but AVX2 not available])
        fi
    ])
fi

dnl ############# System Dependencies

AC_MSG_CHECKING([for special system dependencies])

AC_CANONICAL_HOST
AC_C_CONST

dnl Checks for OS type.
case "$host" in
    *-freebsd*)
        AC_DEFINE([BSD_DERIVED],1,BSD_DERIVED)
        AC_DEFINE([FREEBSD],1,FREEBSD)
        ;;
    *-netbsd*)
        AC_DEFINE([BSD_DERIVED],1,BSD_DERIVED)
        AC_DEFINE([NETBSD],1,NETBSD)
        ;;
    *-openbsd*)
        AC_DEFINE([BSD_DERIVED],1,BSD_DERIVED)
        AC_DEFINE([OPENBSD],1,OPENBSD)
        ;;
    *-apple*)
        AC_DEFINE([BSD_DERIVED],1,BSD_DERIVED)
        AC_DEFINE([MACOS],1,MACOS)
        ;;
    *-linux*)
        AC_DEFINE([SYSV_DERIVED],1,SYSV_DERIVED)
        AC_DEFINE([LINUX],1,LINUX)
        AC_DEFINE([__USE_BSD],1,__USE_BSD)
        AC_DEFINE([__FAVOR_BSD],1,__FAVOR_BSD)
        ;;
    *-solaris*)
        AC_DEFINE([SYSV_DERIVED],1,SYSV_DERIVED)
        AC_DEFINE([SOLARIS],1,SOLARIS)
        ;;
    *-aix*)
        AC_DEFINE([SYSV_DERIVED],1,SYSV_DERIVED)
        AC_DEFINE([AIX],1,AIX)
        ;;
    *-hpux*)
        AC_DEFINE([SYSV_DERIVED],1,SYSV_DERIVED)
        AC_DEFINE([HPUX],1,HPUX)
        ;;
esac

dnl ############## Header Checks
AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([stdint.h])
AC_CHECK_HEADERS([stdlib.h])
AC_CHECK_HEADERS([string.h])
AC_CHECK_HEADERS([strings.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([sys/stat.h])
AC_CHECK_HEADERS([sys/types.h])
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([syslog.h])
AC_CHECK_HEADERS([dirent.h])
AC_CHECK_HEADERS([inttypes.h])
AC_CHECK_HEADERS([stdatomic.h])
AC_CHECK_HEADERS([pthread.h])
AC_CHECK_HEADERS([sys/mman.h])

dnl ############## Function checks
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([strchr])
AC_CHECK_FUNCS([strdup])
AC_CHECK_FUNCS([strerror])
AC_CHECK_FUNCS([inet_pton])
AC_CHECK_FUNCS([inet_ntop])
AC_CHECK_FUNCS([aligned_alloc])
AC_CHECK_FUNCS([posix_memalign])
AC_CHECK_FUNCS([madvise])
AC_CHECK_FUNCS([fsync])
AC_FUNC_MALLOC
AC_FUNC_REALLOC

dnl ############## Type checks
AC_TYPE_SIZE_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

dnl Check for C11 atomics
AC_MSG_CHECKING([for C11 atomics])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
    #include <stdatomic.h>
]], [[
    _Atomic int x = 0;
    atomic_fetch_add(&x, 1);
]])], [
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_C11_ATOMICS], [1], [Define if C11 atomics are available])
], [
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([C11 atomics required. Use a C11-compliant compiler.])
])

AC_CONFIG_HEADERS(include/config.h)
AC_PROG_INSTALL
AC_CONFIG_FILES([Makefile src/Makefile sauron.3 sauron-cli.1])
AC_OUTPUT

BINDIR=`eval echo ${bindir}`; BINDIR=`eval echo ${BINDIR}`;
LIBDIR=`eval echo ${libdir}`; LIBDIR=`eval echo ${LIBDIR}`;
INCDIR=`eval echo ${includedir}`; INCDIR=`eval echo ${INCDIR}`;
MANDIR=`eval echo ${mandir}/${mansubdir}`; MANDIR=`eval echo ${MANDIR}`;

echo ""
echo "-----------------------------------------------"
echo "Sauron IPv4 Scoring Engine v${VERSION}"
echo "-----------------------------------------------"
echo "Host type             : ${host}"
echo "Compiler              : ${CC}"
echo "Compiler flags        : ${CFLAGS}"
echo "Linker flags          : ${LDFLAGS}"
echo "Libraries             : ${LIBS}"
echo ""
echo "Binary                : ${BINDIR}"
echo "Library               : ${LIBDIR}"
echo "Headers               : ${INCDIR}"
echo "Manual pages          : ${MANDIR}"
echo ""
echo "Enable debugging      : ${DEBUG}"
echo "Enable mem debugging  : ${MEM_DEBUG}"
echo "Show mem debugging    : ${SHOW_MEM_DEBUG}"
echo "Security hardening    : ${HARDENING}"
echo "Static analysis       : ${STATIC_ANALYSIS}"
echo "Profiling (gprof)     : ${GPROF}"
echo "Adaptive mutex (VMs)  : ${ADAPTIVE_MUTEX}"
echo "SIMD optimizations    : ${SIMD_ENABLED}"
echo "-----------------------------------------------"
echo ""
