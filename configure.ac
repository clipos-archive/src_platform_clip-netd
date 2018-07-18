# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2009-2018 ANSSI. All Rights Reserved.
AC_INIT([clip-netd],[2.3.3],[clipos@ssi.gouv.fr])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile init/Makefile])

AC_ARG_WITH(stop-script, 
	AC_HELP_STRING([--with-stop-script=path], 
		[Call <path> stop to stop networking (default: /etc/init.d/networking )]),
		[STOP_SCRIPT=$withval],
		[STOP_SCRIPT=/etc/init.d/networking ])
AC_SUBST(STOP_SCRIPT)
AC_MSG_CHECKING(for net stop script)
AC_MSG_RESULT($STOP_SCRIPT)

AC_ARG_WITH(start-script, 
	AC_HELP_STRING([--with-start-script=path], 
		[Call <path> start to start networking (default: /etc/init.d/networking )]),
		[START_SCRIPT=$withval],
		[START_SCRIPT=/etc/init.d/networking ])
AC_SUBST(START_SCRIPT)
AC_MSG_CHECKING(for net start script)
AC_MSG_RESULT($START_SCRIPT)

AC_ARG_WITH(list-script, 
	AC_HELP_STRING([--with-list-script=path], 
		[Call <path> start to generate a list of active wireless cells (default: /sbin/wirelessscan.pl )]),
		[LIST_SCRIPT=$withval],
		[LIST_SCRIPT=/sbin/wirelessscan.pl ])
AC_SUBST(LIST_SCRIPT)
AC_MSG_CHECKING(for wireless list script)
AC_MSG_RESULT($LIST_SCRIPT)


if test -z "$PKG_CONFIG"; then
  PKG_CONFIG=pkg-config
fi
AC_SUBST(PKG_CONFIG)

AC_MSG_CHECKING(that pkg-config runs)
if "$PKG_CONFIG" --version > /dev/null 2>&1 ; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
  AC_MSG_ERROR([*** $PKG_CONFIG missing ***

    \'$PKG_CONFIG --version\' failed to run - make sure it is inside one of the
    directories in your PATH environment variable!

    pkg-config comes with the developement packages for GTK+-2.2, available at:

    with the developement packages for GTK+-2.2, available at:

    http://www.gtk.org])
fi

AC_DEFUN([CLIP_REQUIRE], [
AC_MSG_CHECKING(that $1 (version >= $2) is installed)
if "$PKG_CONFIG" --atleast-version=$2 $1 ; then
  LIBS="$LIBS `$PKG_CONFIG --libs $1`"
  CFLAGS="$CFLAGS `$PKG_CONFIG --cflags $1`"
  AC_MSG_RESULT(yes) 
else
  AC_MSG_RESULT(no)
  if "$PKG_CONFIG" --exists $1 ; then
      AC_MSG_ERROR(Current version is only `"$PKG_CONFIG" "$1" --modversion`)
  else
      AC_MSG_ERROR(Package is not installed)
  fi
fi
])

CLIP_REQUIRE(clip, 1.2.3)

AC_OUTPUT
