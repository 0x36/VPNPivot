#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([VPNPivot], [1.0], [simo.ghannam@gmail.com])
AM_INIT_AUTOMAKE()
#AC_CONFIG_SRCDIR([src/crypto.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([crypto], [RSA_generate_key])
AC_CHECK_LIB([ssl], [SSL_library_init])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gethostbyname inet_ntoa memset select socket strchr strdup])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
