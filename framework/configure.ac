AC_INIT([setroubleshoot], [3.1.7],
        [http://bugzilla.redhat.com/bugzilla/enter_bug.cgi?product=setroubleshoot])

AC_CONFIG_SRCDIR(src/__init__.py)
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
af     bs     et     hy     lt   nso    sq        vi 	\
aln    ca     eu_ES  id     lv   or     sr@latin  vi_VN	\
am     cs_CZ  fa_IR  is     mai  pa     sr        zh_CN	\
ar     cs     fa     it     mk   pl     sv        zh_HK	\
as     cy     fi     ja_JP  ml   pt_BR  ta_IN     zh_TW	\
ast    da     fr     ja     mr   pt     ta        zu	\
bal    de_CH  gl     ka     ms   ro     te	\
be     de     gu     kn     my   ru     tg	\
bg     el     he     ko     nb   ru_RU  th	\
bn_BD  en_GB  hi     ku     nds  si     tr	\
bn_IN  es_ES  hr     lo     nl   sk     uk	\
bn     es     hu     lt_LT  nn   sl     ur	\
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
src/sesearch/Makefile
src/default_encoding/Makefile
test/Makefile
])

AC_OUTPUT
