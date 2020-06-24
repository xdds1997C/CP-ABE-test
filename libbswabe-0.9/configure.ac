dnl Process this file with autoconf to produce a configure script.
AC_PREREQ(2.61)
AC_INIT([libbswabe], [0.9], [bethenco@cs.berkeley.edu])
AC_CONFIG_SRCDIR([bswabe.h])

dnl First, standard system stuff.

dnl  language and compiler support
AC_MSG_CHECKING(whether to enable debugging)
debug_default="no"
AC_ARG_ENABLE(debug, [  --enable-debug=[no/yes]  turn on debugging
                          [default=$debug_default]],, enable_debug=$debug_default)
if test "x$enable_debug" = "xyes"; then
  CFLAGS="-g -Wall"
  LDFLAGS="-g -Wall"
  AC_DEFINE(BSWABE_DEBUG)
  AC_MSG_RESULT(yes)
else
  CFLAGS="-O3 -Wall"
  LDFLAGS="-O3 -Wall"
  AC_MSG_RESULT(no)
fi
AC_PROG_CC
AC_LANG(C)
AC_C_CONST
AC_TYPE_UINT32_T

dnl  standard headers
AC_HEADER_STDC
AC_CHECK_HEADERS([stdint.h stdlib.h string.h],,
 [AC_MSG_ERROR([could not find all required headers stdint.h, stdlib.h, string.h])])

dnl  specific library functions
AC_FUNC_MALLOC
AC_FUNC_ALLOCA
AC_FUNC_VPRINTF
AC_CHECK_LIB(crypto, SHA1,,
 [AC_MSG_ERROR([please install the OpenSSL crypto library, libcrypto.])])
AC_CHECK_FUNCS([strdup],,
 [AC_MSG_ERROR([could not link to required function strdup])])

dnl Now, we check for specific packages we need.
AM_PATH_GLIB_2_0([2.0.0])
GMP_4_0_CHECK
PBC_CHECK

dnl Specify the output.
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
