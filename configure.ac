# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# $Id$

# Copyright 2006 Lennart Poettering
#
# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License.  You
# may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

AC_PREREQ(2.57)
AC_INIT([mod_dnssd],[0.2],[mzzbqqaffq (at) 0pointer (dot) net])
AC_CONFIG_SRCDIR([src/mod_dnssd.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign 1.9 -Wall])

AC_SUBST(PACKAGE_URL, [http://0pointer.de/lennart/projects/mod_dnssd/])

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_MAKE_SET

test_gcc_flag() {
    AC_LANG_CONFTEST([int main() {}])
    $CC -c conftest.c $CFLAGS $@ > /dev/null 2> /dev/null
    ret=$?
    rm -f conftest.o
    return $ret
}

# If using GCC specify some additional parameters
if test "x$GCC" = "xyes" ; then

    DESIRED_FLAGS="-Wall -W -Wextra -pedantic -pipe -Wformat -Wold-style-definition -Wdeclaration-after-statement -Wfloat-equal -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes -Wredundant-decls -Wmissing-noreturn -Wshadow -Wendif-labels -Wpointer-arith -Wbad-function-cast -Wcast-qual -Wcast-align -Wwrite-strings -Winline"

    if test "x$HAVE_NETLINK" = "xyes" ; then
        # Test whether rtnetlink.h can be included when compiled with -std=c99
        # some distributions (e.g. archlinux) have broken headers that dont
        # define __u64 with -std=c99
        AC_MSG_CHECKING([checking whether rtnetlink.h can be included with -std=c99])
        OLDCFLAGS="$CFLAGS"
        CFLAGS="-std=c99"
        AC_TRY_COMPILE([#include <linux/rtnetlink.h>], [],
            use_stdc99=yes, use_stdc99=no)

        if test x"$use_stdc99" = xyes; then
            DESIRED_FLAGS="-std=c99 $DESIRED_FLAGS"
            AC_MSG_RESULT([yes])
        else
            AC_MSG_RESULT([no])
        fi

        CFLAGS="$OLDCFLAGS"
    else
        DESIRED_FLAGS="-std=c99 $DESIRED_FLAGS"
    fi

    for flag in $DESIRED_FLAGS ; do
        AC_MSG_CHECKING([whether $CC accepts $flag])
        if test_gcc_flag $flag ; then 
           CFLAGS="$CFLAGS $flag"
           AC_MSG_RESULT([yes])
        else
           AC_MSG_RESULT([no])
        fi
    done 
fi

AC_ARG_WITH(apxs,
    AS_HELP_STRING(--with-apxs=PATH,/path/to/apxs),
    [ AC_PATH_PROGS(APXS, [apxs2 apxs], "notfound", "$withval:$PATH") ], 
    [ AC_PATH_PROGS(APXS, [apxs2 apxs], "notfound", "/usr/local/apache/bin:/usr/local/bin:/usr/sbin:$PATH")])

if test "x$APXS" = "xnotfound" ; then
    AC_MSG_ERROR([*** Sorry, could not find apxs ***])
fi

AC_ARG_WITH(apachectl,
    AS_HELP_STRING(--with-apachectl=PATH,/path/to/apachectl),
    [ AC_PATH_PROGS(APACHECTL, [apache2ctl apachectl], "notfound", "$withval:$PATH") ], 
    [ AC_PATH_PROGS(APACHECTL, [apache2ctl apachectl], "notfound", "/usr/local/apache/bin:/usr/local/bin:/usr/sbin:$PATH")])

PKG_CHECK_MODULES(AVAHI, [ avahi-client >= 0.6 ])
AC_SUBST(AVAHI_CFLAGS)
AC_SUBST(AVAHI_LIBS)

# LYNX documentation generation
AC_ARG_ENABLE(lynx,
        AS_HELP_STRING(--disable-lynx,Turn off lynx usage for documentation generation),
[case "${enableval}" in
  yes) lynx=yes ;;
  no)  lynx=no ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --disable-lynx) ;;
esac],[lynx=yes])

if test x$lynx = xyes ; then
   AC_CHECK_PROG(have_lynx, lynx, yes, no)

   if test x$have_lynx = xno ; then
     AC_MSG_ERROR([*** Sorry, you have to install lynx or use --disable-lynx ***])
   fi
fi

AM_CONDITIONAL([USE_LYNX], [test "x$lynx" = xyes])

AC_CONFIG_FILES([src/Makefile Makefile doc/Makefile doc/README.html])
AC_OUTPUT
