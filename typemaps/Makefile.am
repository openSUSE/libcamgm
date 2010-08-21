
SUBDIRS = perl5

swigdir   = @SWIG_LIB@
typefiles = $(wildcard $(srcdir)/*.i)

EXTRA_DIST = $(typefiles)

install-data-local:
	mkdir -p $(DESTDIR)/$(swigdir)
	cp -a $(typefiles) $(DESTDIR)/$(swigdir)
