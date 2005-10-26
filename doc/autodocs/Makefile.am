#
# Makefile.am for limal-ca-mgm/doc/autodocs
#

htmldir = $(docdir)/autodocs

html_DATA = index.html $(wildcard *.html *.png) doxygen.css @RPMNAME@.tag

CLEANFILES = $(html_DATA) doxygen.log doxygen.conf installdox

doxygen.css @RPMNAME@.tag: index.html

header_dir = $(srcdir)/../../src/limal/ca-mgm/
source_dir = $(srcdir)/../../src/

index.html: $(header_dir)/*.hpp $(srcdir)/../../doc/examples/*.cpp
	${LIMALDOXYGEN} --prefix=$(prefix) PROJECT_NAME=@RPMNAME@ TAGFILES= \
    EXAMPLE_PATH=$(srcdir)/../../doc/examples/ \
    INPUT="$(header_dir)"
