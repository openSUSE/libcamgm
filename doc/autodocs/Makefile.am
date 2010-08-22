#
# Makefile.am for limal-ca-mgm/doc/autodocs
#

htmldir = $(docdir)/autodocs

html_DATA = index.html $(wildcard *.html *.png *.css *.gif) @RPMNAME@.tag

CLEANFILES = $(html_DATA) doxygen.log installdox *~

doxygen.css @RPMNAME@.tag: index.html

headers = $(wildcard $(srcdir)/../../src/limal/*.hpp $(srcdir)/../../src/limal/ca-mgm/*.hpp)

index.html: $(headers) $(srcdir)/../../doc/examples/*.cpp
	doxygen doxygen.conf

EXTRA_DIST = doxygen.conf


