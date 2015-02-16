#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([rtspextr], [0.1.2], [p.wolneykien@metrotek.spb.ru])

AC_CONFIG_SRCDIR([rtspextr.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE([enable])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([pcap], [pcap_open_dead], [HAVE_PCAP=1])
if test "$HAVE_PCAP" = "1"; then
  AC_DEFINE([PCAP], [1], [libpcap support flag])
  AC_CHECK_HEADERS([pcap/pcap.h pcap/bpf.h])
fi

enable_udp=yes
AC_ARG_ENABLE([udp],
    [AS_HELP_STRING([--disable-udp],
                    [build with UDP support disabled])])

if test "$enable_udp" = "yes"; then
  AC_DEFINE([UDP], [1], [UDP socket support flag])
  AC_CHECK_HEADERS([arpa/inet.h netinet/in.h sys/socket.h])
fi

enable_unix=yes
AC_ARG_ENABLE([unix],
    [AS_HELP_STRING([--disable-unix],
                    [build with UNIX socket support disabled])])

if test "$enable_unix" = "yes"; then
  AC_DEFINE([UNIX], [1], [UNIX socket support flag])
  AC_CHECK_HEADERS([arpa/inet.h netinet/in.h sys/socket.h])
fi

# Checks for common header files.
AC_CHECK_HEADERS([stdint.h stdlib.h string.h])

AM_CONDITIONAL(PCAP, [test "$HAVE_PCAP" = "1"])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([gettimeofday memchr memmove memset socket strtol strtoul])

# Output
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
