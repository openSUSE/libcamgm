#
# Makefile.am for limal-ca-mgm/doc
#

SUBDIRS = autodocs

htmldir = $(docdir)
xml_files =  $(wildcard $(srcdir)/*.xml) 

html_DATA = $(wildcard html/*.html) \
	    html/index.html \
	    html/limaldocs.css

pdf: limal-ca-mgm.pdf

html/index.html: $(xml_files)
	XML_CATALOG_FILES=@XML_CATALOG@ \
	@XSLTPROC@ @XSLTPROC_FLAGS@ --xinclude \
	@STYLESHEET_HTML@ limal-ca-mgm.xml

limal-ca-mgm.fo: $(xml_files)
	XML_CATALOG_FILES=@XML_CATALOG@ \
	@XSLTPROC@ @XSLTPROC_FLAGS@ --xinclude \
	-o $@ @STYLESHEET_PDF@  limal-ca-mgm.xml

limal-ca-mgm.pdf: limal-ca-mgm.fo
	fop -q $< $@


html/limaldocs.css: html/index.html
	cp @STYLESHEET_CSS@ html
	cp -a $(limaldatadir)/docbook/images html

EXTRA_DIST = $(xml_files) examples/*.cpp

CLEANFILES =  $(html_DATA)

clean-local:
	rm -rf html

install-data-local:
	mkdir -p $(DESTDIR)$(htmldir)
	cp -a $(srcdir)/html/images $(DESTDIR)$(htmldir)
	cp -a $(srcdir)/examples $(DESTDIR)$(htmldir)

