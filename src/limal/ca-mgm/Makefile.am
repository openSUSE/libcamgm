#
# Makefile.am for limal-ca-mgm/src/limal/ca-mgm
#

pkglimalincludedir = $(limalincludedir)/ca-mgm

# these go to $(pkglimalincludedir)
pkglimalinclude_HEADERS =   \
	CaMgm.hpp	    \
	config.h

#
# replace some constants only
#
config.h.in: Makefile
config.h: config.h.in
	$(top_builddir)/config.status --file=$@:$<

EXTRA_DIST = config.h.in
DISTCLEANFILES = config.h

