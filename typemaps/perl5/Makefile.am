swigdir   = @SWIG_LIB@
typefiles = $(wildcard $(srcdir)/*.i)

EXTRA_DIST = $(typefiles)
CLEANFILES = *~
MAINTAINERCLEANFILES = Makefile.in

install-data-local:
	mkdir -p $(DESTDIR)$(swigdir)/perl5
	cp -a $(typefiles) $(DESTDIR)$(swigdir)/perl5
