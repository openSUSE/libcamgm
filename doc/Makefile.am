#
# Makefile.am for limal-ca-mgm/doc
#

SUBDIRS = autodocs

EXTRA_DIST = examples/*.cpp

CLEANFILES = *~

all:

clean-local:
	rm -rf html

install-data-local:
	cp -a $(srcdir)/examples $(DESTDIR)$(docdir)

