#
# Makefile.am for limal-ca-mgm/doc/autodocs
#

htmldir = $(docdir)/autodocs

html_DATA = index.html $(wildcard *.html *.png *.css *.gif) @RPMNAME@.tag

CLEANFILES = $(html_DATA) doxygen.log doxygen.conf installdox

doxygen.css @RPMNAME@.tag: index.html

header_dir = $(srcdir)/../../src/limal/ca-mgm/
source_dir = $(srcdir)/../../src/

index.html: $(header_dir)/*.hpp $(srcdir)/../../doc/examples/*.cpp
	${LIMALDOXYGEN} --prefix=$(prefix) PROJECT_NAME=@RPMNAME@ \
        TAGFILES="/usr/share/doc/packages/blocxx/html/blocxx.tag=/usr/share/doc/packages/blocxx/html/ \
                  /usr/share/doc/packages/limal/autodocs/limal.tag=/usr/share/doc/packages/limal/autodocs/" \
    EXAMPLE_PATH=$(srcdir)/../../doc/examples/ \
    PREDEFINED="blocxx=BLOCXX_NAMESPACE blocxx4=BLOCXX_NAMESPACE LIMAL_NAMESPACE=limal CA_MGM_NAMESPACE=ca_mgm" \
    INPUT="$(header_dir)"
