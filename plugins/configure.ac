AC_INIT([setroubleshoot-plugins], [3.0.32],
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
af     bs     et     hy     lt   nso    sq        vi 	\
aln    ca     eu_ES  id     lv   or     sr@latin  vi_VN	\
am     cs_CZ  fa_IR  is     mai  pa     sr        zh_CN	\
ar     cs     fa     it     mk   pl     sv        zh_HK	\
as     cy     fi     ja_JP  ml   pt_BR  ta_IN     zh_TW	\
ast    da     fr     ja     mr   pt     ta        zu	\
bal    de_DE  de_CH  gl     ka   ms     ro        te	\
be     de     gu     kn     my   ru     tg	\
bg     el     he     ko     nb   ru_RU  th	\
bn_BD  en_GB  hi     ku     nds  si     tr	\
bn_IN  es_ES  hr     lo     nl   sk     uk	\
bn     es     hu     lt_LT  nn   sl     ur	\
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
