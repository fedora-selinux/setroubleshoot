SUBDIRS = po src

EXTRA_DIST = 				\
	intltool-extract.in		\
	intltool-merge.in		\
	intltool-update.in		\
	$(NULL)

pkgdoc_DATA =		\
	AUTHORS		\
	COPYING		\
	ChangeLog	\
	README		\
	$(NULL)


rpm: dist
	rpmbuild -ta $(PACKAGE_NAME)-$(PACKAGE_VERSION).tar.gz

srpm: dist
	rpmbuild --define "_sourcedir `pwd`" --define "_srcrpmdir `pwd`" --define "_specdir `pwd`" -ts @PACKAGE@-@VERSION@.tar.gz

VERSION_FILE = configure.ac
