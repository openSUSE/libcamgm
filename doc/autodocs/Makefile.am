#
# Makefile.am for limal-ca-mgm/doc/autodocs
#

htmldir = $(docdir)/autodocs

html_DATA = $(wildcard *.html *.png *.css *.gif) @RPMNAME@.tag

CLEANFILES = $(html_DATA) doxygen.log installdox *~

doxygen.css @RPMNAME@.tag: index.html

headers = $(wildcard $(srcdir)/../../src/ca-mgm/*.hpp)

index.html: $(headers) $(srcdir)/../../doc/examples/*.cpp doxygen.conf
	@DOXYGEN_COMMAND@ doxygen.conf

EXTRA_DIST = doxygen.conf


