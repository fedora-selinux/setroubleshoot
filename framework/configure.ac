AC_INIT([setroubleshoot], [3.2.26.2],
        [http://bugzilla.redhat.com/bugzilla/enter_bug.cgi?product=setroubleshoot])

AC_CONFIG_SRCDIR(src/setroubleshoot/__init__.py)
AC_CONFIG_AUX_DIR([.])

AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE

PKG_CHECK_MODULES([DBUS], [dbus-1])
PKG_CHECK_MODULES([GTK], [gtk+-2.0])
PKG_CHECK_MODULES([GIO], [gio-unix-2.0])
PKG_CHECK_MODULES([NOTIFY], [libnotify])
PKG_CHECK_MODULES([SEAPPLET], [gtk+-2.0 gio-unix-2.0 libnotify dbus-glib-1])

# make sure we keep ACLOCAL_FLAGS around for maintainer builds to work
AC_SUBST(ACLOCAL_AMFLAGS, "\${ACLOCAL_FLAGS}")

GETTEXT_PACKAGE=setroubleshoot
AC_SUBST(GETTEXT_PACKAGE)
AM_GLIB_GNU_GETTEXT
IT_PROG_INTLTOOL

ALL_LINGUAS="\
af am ang ar as ast az az_IR be be@latin bg bn bn_IN br bs ca ca@valencia \
crh cs cy da de dz el en en_CA en_GB en@shaw eo es et eu fa fi fr ga gl gu \
he hi hr hu hy ia id io is it ja ka kg kk kn ko ku lg li lt lv mai mi mk \
ml mn mr ms my nb nds ne nl nn nso oc or pa pl ps pt pt_BR ro ru rw si sk \
sl sq sr sr@ije sr@latin sv ta te th tk tr tt ug uk ur uz uz@cyrillic vi \
wa xh yi zh_CN zh_HK zh_TW
"

AC_PROG_LN_S
AM_PATH_PYTHON
LIBCAP_NG_PATH

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
audispdir="\${sysconfdir}/audisp/plugins.d"
daemon_name="\${PACKAGE_NAME}d"
pid_file="\${localstatedir}/run/\${daemon_name}.pid"

AC_ARG_WITH([plugindir], AC_HELP_STRING([--with-plugindir=DIR],
                                        [plugin installation directory]),
            [plugindir="$with_plugindir"],
            [plugindir="\${datadir}/setroubleshoot/plugins"])

AC_SUBST(pkgconfigdir)
AC_SUBST(pkgdocdir)
AC_SUBST(pkgguidir)
AC_SUBST(pkglibexecdir)
AC_SUBST(pkglogdir)
AC_SUBST(plugindir)
AC_SUBST(pkgvardatadir)
AC_SUBST(pkgrundir)
AC_SUBST(auditlibdir)
AC_SUBST(audispdir)
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
