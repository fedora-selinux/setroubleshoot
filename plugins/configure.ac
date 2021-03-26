AC_INIT([setroubleshoot-plugins], [3.3.14],
        [http://bugzilla.redhat.com/bugzilla/enter_bug.cgi?product=setroubleshoot])
AC_CONFIG_SRCDIR(src/Makefile.am)
AC_CONFIG_AUX_DIR([.])

AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE


# make sure we keep ACLOCAL_FLAGS around for maintainer builds to work
AC_SUBST(ACLOCAL_AMFLAGS, "\${ACLOCAL_FLAGS}")

GETTEXT_PACKAGE=setroubleshoot-plugins
AC_SUBST(GETTEXT_PACKAGE)
AM_GLIB_GNU_GETTEXT
IT_PROG_INTLTOOL
ALL_LINGUAS="\
as bg bn bn_IN ca cs da de el en_GB es eu fi fr fur gl gu he hi hr hu it ja \
kn ko mai ml mr ms nb_NO nds nl nn or pa pl pt pt_BR ru si sk sr sr_Latn sv \
ta te th tr uk zh_CN zh_TW
"

AC_PROG_LN_S
AM_PATH_PYTHON([3])

pkgdocdir="\${datadir}/doc/$PACKAGE_NAME-$PACKAGE_VERSION"

AC_ARG_WITH([plugindir], AC_HELP_STRING([--with-plugindir=DIR],
                                        [plugin installation directory]),
            [plugindir="$with_plugindir"],
            [plugindir="\${datadir}/setroubleshoot/plugins"])

AC_SUBST(pkgdocdir)
AC_SUBST(plugindir)

AC_CONFIG_FILES([
Makefile
src/Makefile
po/Makefile.in
])

AC_OUTPUT
