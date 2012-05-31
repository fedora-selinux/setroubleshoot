AC_INIT([setroubleshoot-plugins], [3.0.40],
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
af am ang ar as ast az az_IR be be@latin bg bn bn_IN br bs ca ca@valencia \
crh cs cy da de dz el en en_CA en_GB en@shaw eo es et eu fa fi fr ga gl gu \
he hi hr hu hy ia id io is it ja ka kg kk kn ko ku lg li lt lv mai mi mk \
ml mn mr ms my nb nds ne nl nn nso oc or pa pl ps pt pt_BR ro ru rw si sk \
sl sq sr sr@ije sr@latin sv ta te th tk tr tt ug uk ur uz uz@cyrillic vi \
wa xh yi zh_CN zh_HK zh_TW
"

AC_PROG_LN_S
AM_PATH_PYTHON

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
