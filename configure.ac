AC_INIT([xenoeye], [23.11], [vm@xenoeye.com])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([check-news foreign silent-rules subdir-objects -Wall])

AC_PROG_MKDIR_P

AM_MAINTAINER_MODE

AM_PROG_AR
AC_PROG_CC
AM_PROG_CC_C_O
AC_CONFIG_HEADERS([config.h])
LT_INIT

AC_MSG_CHECKING(whether compiler understands -Wall -Wextra -pedantic)
old_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -Wall -Wextra -pedantic"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],
  AC_MSG_RESULT(yes),
  AC_MSG_RESULT(no)
  CFLAGS="$old_CFLAGS")

AC_SEARCH_LIBS([pcap_open_live], [pcap], [], [
  AC_MSG_ERROR([unable to find the pcap_open_live() function])
])

AC_SEARCH_LIBS([__atomic_load_16], [atomic], [], [
  AC_MSG_ERROR([unable to find the __atomic_load_16() function])
])

AC_SEARCH_LIBS([log], [m], [], [
  AC_MSG_ERROR([unable to find the log() function])
])

#musl don't have a getprotobynumber_r function
AC_CHECK_FUNC([getprotobynumber_r], [AC_DEFINE([HAVE_GETPROTOBYNUMBER_R], [1],
                               [Define if getprotobynumber_r exists.])])

# pthreads

AX_PTHREAD([
  LIBS="$PTHREAD_LIBS $LIBS"
  CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
  CC="$PTHREAD_CC"], AC_MSG_ERROR([Missing POSIX threads support]))

AM_SILENT_RULES([yes])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_MACRO_DIRS([m4])
AC_OUTPUT
