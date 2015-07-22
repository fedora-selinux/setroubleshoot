bin_SCRIPTS =				\
	sealert				\
	$(NULL)

sedispatch_LDADD = $(CAPNG_LDADD) $(DBUS_LIBS) -lauparse -lselinux
sedispatch_SOURCES = 			\
	sedispatch.c			\
	sedbus.c

seapplet_LDADD = $(SEAPPLET_LIBS) -lauparse -lselinux
seapplet_SOURCES = 			\
	sedbus.h			\
	seapplet.c			\
	sedbus.c

bin_PROGRAMS = 				\
	seapplet			\
	$(NULL)

sbin_PROGRAMS = 			\
	sedispatch			\
	$(NULL)

AM_CPPFLAGS =  $(SEAPPLET_CFLAGS)

DEFS = @DEFS@ -DLOCALEDIR=\"$(localedir)\"

sbin_SCRIPTS =				\
	setroubleshootd			\
	$(NULL)

pkglibexec_SCRIPTS =            	\
        $(NULL)

pkgdir = $(datarootdir)/setroubleshoot
pkg_SCRIPTS =			\
	SetroubleshootFixit.py		\
	updater.py

pkgconfig_DATA =			\
	setroubleshoot.conf		\
	$(NULL)

audisp_DATA =				\
	sedispatch.conf			\
	$(NULL)

PYTHON_FILES =				\
	setroubleshoot/access_control.py \
	setroubleshoot/analyze.py \
	setroubleshoot/audit_data.py \
	setroubleshoot/avc_audit.py \
	setroubleshoot/browser.py \
	setroubleshoot/email_alert.py \
	setroubleshoot/errcode.py \
	setroubleshoot/gui_utils.py \
	setroubleshoot/html_util.py \
	setroubleshoot/__init__.py \
	setroubleshoot/Plugin.py \
	setroubleshoot/rpc_interfaces.py \
	setroubleshoot/rpc.py \
	setroubleshoot/serverconnection.py \
	setroubleshoot/server.py \
	setroubleshoot/signature.py \
	setroubleshoot/util.py \
	setroubleshoot/uuid.py \
	setroubleshoot/xml_serialize.py

EXTRA_DIST =				\
	setup.py			\
	default_encoding.c		\
	$(PYTHON_FILES)			\
	$(pkg_SCRIPTS)			\
	$(sbin_SCRIPTS)			\
	$(bin_SCRIPTS)			\
	$(audisp_DATA)			\
	config.py.in			\
	$(NULL)

setroubleshoot/config.py: config.py.in Makefile
	sed \
	-e s!\@PACKAGE_NAME\@!$(PACKAGE_NAME)!			\
	-e s!\@PACKAGE_VERSION\@!$(PACKAGE_VERSION)!		\
	-e s!\@daemon_name\@!$(daemon_name)!			\
	-e s!\@pkgdatadir\@!$(pkgdatadir)!			\
	-e s!\@pkglibdir\@!$(pkglibdir)!			\
	-e s!\@pkglibexecdir\@!$(pkglibexecdir)!		\
	-e s!\@pkgguidir\@!$(pkgguidir)!			\
	-e s!\@plugindir\@!$(plugindir)!			\
	-e s!\@pkgvardatadir\@!$(pkgvardatadir)!		\
	-e s!\@pkgrundir\@!$(pkgrundir)!			\
	-e s!\@pkgconfigdir\@!$(pkgconfigdir)!			\
	-e s!\@pkglogdir\@!$(pkglogdir)!			\
	-e s!\@pid_file\@!$(pid_file)!				\
	-e s!\@html_browser_open\@!$(html_browser_open)!	\
	< $< > $@

setroubleshoot.conf: setroubleshoot/config.py
	$(PYTHON) setroubleshoot/config.py -d > $@

DISTCLEANFILES = setroubleshoot/config.py
BUILT_SOURCES  = setroubleshoot/config.py

all-am: python-build

python-build:
	$(PYTHON) setup.py build

install-exec-hook:
	$(PYTHON) setup.py install `test -n "$(DESTDIR)" && echo --root $(DESTDIR)`

uninstall-hook:
	$(PYTHON) setup.py uninstall `test -n "$(DESTDIR)" && echo --root $(DESTDIR)`
