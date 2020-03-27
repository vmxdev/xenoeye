AC_INIT([xenoeye], [20.03], [vm@xenoeye.com])
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

# pthreads

AX_PTHREAD([
  LIBS="$PTHREAD_LIBS $LIBS"
  CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
  CC="$PTHREAD_CC"], AC_MSG_ERROR([Missing POSIX threads support]))

AM_SILENT_RULES([yes])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_MACRO_DIRS([m4])
AC_OUTPUT
