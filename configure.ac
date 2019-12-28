AC_INIT([xenoeye], [18.12], [vm@xenoeye.com])
AM_INIT_AUTOMAKE([foreign -Wall -Werror subdir-objects])
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])

#pthreads
AC_SEARCH_LIBS([pthread_create], [pthread], [], [
  AC_MSG_ERROR([pthreads support required])
])

AC_PROG_MKDIR_P

AC_MSG_CHECKING(whether compiler understands -Wall -Wextra -pedantic)
old_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -Wall -Wextra -pedantic"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],
  AC_MSG_RESULT(yes),
  AC_MSG_RESULT(no)
  CFLAGS="$old_CFLAGS")

AM_SILENT_RULES([yes])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
