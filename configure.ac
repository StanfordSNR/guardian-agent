#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([fine-auth], [0.01], [keithw@cs.stanford.edu])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_SRCDIR([libaba/address.hh])
AC_CONFIG_HEADERS([config.h])
LT_INIT(dlopen)

# Add picky CXXFLAGS
CXX17_FLAGS="-std=c++17 -pthread -fPIC"
PICKY_CXXFLAGS="-pedantic -Wall -Wextra -Werror"
AC_SUBST(ARFLAGS, "cr")
AC_SUBST(AR_FLAGS, "cr")
AC_SUBST([CXX17_FLAGS])
AC_SUBST([PICKY_CXXFLAGS])

# Checks for programs.
AC_PROG_CXX

AC_CHECK_PROG([PROTOC], [protoc], [protoc])
AS_IF([test "x${PROTOC}" == "x"],
    [AC_MSG_ERROR([ProtoBuf compiler "protoc" not found.])])
AC_CHECK_PROG([PROTOCGENGO], [protoc-gen-go], [protoc-gen-go])
AS_IF([test "x${PROTOCGENGO}" == "x"],
    [AC_MSG_ERROR([ProtoBuf Go compiler "protoc-gen-go" not found.])])

# Checks for libraries.

PKG_CHECK_MODULES(PROTOBUF, protobuf >= 3.0.0)
AC_SUBST(PROTOBUF_LIBS)
AC_SUBST(PROTOBUF_CFLAGS)
AC_SUBST(PROTOBUF_VERSION)

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT16_T

# Checks for library functions.

AC_CONFIG_FILES([Makefile proto/Makefile libaba/Makefile gobuild/Makefile])
AC_OUTPUT
