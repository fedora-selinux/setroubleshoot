AC_INIT([setroubleshoot], [3.3.26],
        [http://bugzilla.redhat.com/bugzilla/enter_bug.cgi?product=setroubleshoot])

AC_CONFIG_SRCDIR(src/setroubleshoot/__init__.py)
AC_CONFIG_AUX_DIR([.])

AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE

PKG_CHECK_MODULES([DBUS], [dbus-1])
PKG_CHECK_MODULES([GIO], [gio-unix-2.0])
PKG_CHECK_MODULES([NOTIFY], [libnotify])
PKG_CHECK_MODULES([SEAPPLETLEGACY], [gtk+-2.0 gio-unix-2.0 libnotify dbus-glib-1],
				    [seappletlegacy=yes], [seappletlegacy=no])
PKG_CHECK_MODULES([SEAPPLET], [gtk+-3.0])
# auparse_set_eoe_timeout() requires libauparse 3.0.1
PKG_CHECK_MODULES([SEDISPATCH], [auparse >= 3.0.1])

# make sure we keep ACLOCAL_FLAGS around for maintainer builds to work
AC_SUBST(ACLOCAL_AMFLAGS, "\${ACLOCAL_FLAGS}")

GETTEXT_PACKAGE=setroubleshoot
AC_SUBST(GETTEXT_PACKAGE)
AM_GLIB_GNU_GETTEXT
IT_PROG_INTLTOOL

ALL_LINGUAS="\
as bg bn bn_IN ca cs da de el en_GB es eu fi fr fur gl gu he hi hr hu it ja \
kn ko mai ml mr ms nb nds nl nn or pa pl pt pt_BR ru si sk sr sr@latin sv ta \
te th tr uk zh_CN zh_TW
"

AC_PROG_LN_S
LIBCAP_NG_PATH

AM_PATH_PYTHON([3])
AC_MSG_CHECKING([for the selinux python3 module])
python_module_result=`$PYTHON -c "import selinux" 2>&1`
if test -z "$python_module_result"; then
	AC_MSG_RESULT([yes])
else
	AC_MSG_RESULT([no])
	AC_MSG_ERROR([cannot import Python3 module selinux
                   Please check your Python3 installation. The error was:
                   $python_module_result])
fi

AC_MSG_CHECKING([for the gi python3 module])
python_module_result=`$PYTHON -c "import gi" 2>&1`
if test -z "$python_module_result"; then
	AC_MSG_RESULT([yes])
else
	AC_MSG_RESULT([no])
	AC_MSG_ERROR([cannot import Python3 module gi.
                   Please check your Python3 installation. The error was:
                   $python_module_result])
fi

AC_MSG_CHECKING([for the Notify python3 module])
python_module_result=`$PYTHON -c "import gi; gi.require_version('Notify', '0.7'); from gi.repository import Notify" 2>&1`
if test -z "$python_module_result"; then
	AC_MSG_RESULT([yes])
else
	AC_MSG_RESULT([no])
	AC_MSG_ERROR([cannot import Python3 module Notify.
                   Please check your Python3 installation. The error was:
                   $python_module_result])
fi

AC_MSG_CHECKING([for the dasbus python3 module])
python_module_result=`$PYTHON -c "import dasbus" 2>&1`
if test -z "$python_module_result"; then
	AC_MSG_RESULT([yes])
else
	AC_MSG_RESULT([no])
	AC_MSG_ERROR([cannot import Python3 module dasbus.
                   Please check your Python3 installation. The error was:
                   $python_module_result])
fi


AC_PATH_PROGS([html_browser_open], [xdg-open htmlview])
if test -z $html_browser_open; then
    AC_MSG_ERROR([cannot find utility to launch browser])
fi

pkgconfigdir="\${sysconfdir}/$PACKAGE_NAME"
pkgdocdir="\${datadir}/doc/$PACKAGE_NAME-$PACKAGE_VERSION"
pkgguidir="\${pkgdatadir}/gui"
#pkglibexecdir="\${libexecdir}/$PACKAGE_NAME"
pkglogdir="\${localstatedir}/log/$PACKAGE_NAME"
pkgvardatadir="\${localstatedir}/lib/$PACKAGE_NAME"
pkgrundir="\${localstatedir}/run/$PACKAGE_NAME"
auditlibdir="\${libdir}/audit"
daemon_name="\${PACKAGE_NAME}d"
pid_file="\${localstatedir}/run/\${daemon_name}.pid"

AC_ARG_WITH([plugindir], AC_HELP_STRING([--with-plugindir=DIR],
                                        [plugin installation directory]),
            [plugindir="$with_plugindir"],
            [plugindir="\${datadir}/setroubleshoot/plugins"])

AC_ARG_WITH([auditpluginsdir], AC_HELP_STRING([--with-auditpluginsdir=DIR],
[audit plugins installation directory (default=/etc/audisp/plugins.d/)]),
[auditpluginsdir="$with_auditpluginsdir"],
[auditpluginsdir="\${sysconfdir}/auditsp/plugins.d"])


AC_ARG_ENABLE([seappletlegacy],
    [AC_HELP_STRING([--enable-seappletlegacy], [build seappletlegacy (default=no)])],
    [case "${enableval}" in
      yes) seappletlegacy=yes ;;
      no)  seappletlegacy=no ;;
      *) AC_MSG_ERROR([bad value ${enableval} for --enable-seappletlegacy]) ;;
    esac],[seappletlegacy=no])

AM_CONDITIONAL([ENABLE_SEAPPLETLEGACY], test "$seappletlegacy" = yes)


AC_SUBST(pkgconfigdir)
AC_SUBST(pkgdocdir)
AC_SUBST(pkgguidir)
AC_SUBST(pkglibexecdir)
AC_SUBST(pkglogdir)
AC_SUBST(plugindir)
AC_SUBST(pkgvardatadir)
AC_SUBST(pkgrundir)
AC_SUBST(auditlibdir)
AC_SUBST(auditpluginsdir)
AC_SUBST(daemon_name)
AC_SUBST(pid_file)
AC_SUBST(html_browser_open)

AC_CONFIG_FILES([
Makefile
doc/Makefile
gui/Makefile
po/Makefile.in
src/Makefile
test/Makefile
])

AC_OUTPUT
