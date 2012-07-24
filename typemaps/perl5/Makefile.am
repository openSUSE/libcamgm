swigdir   = @SWIG_LIB@
typefiles = $(wildcard $(srcdir)/*.i)
swgfiles  = $(wildcard $(srcdir)/*.swg)

EXTRA_DIST = $(typefiles) $(swgfiles)
CLEANFILES = *~
MAINTAINERCLEANFILES = Makefile.in

install-data-local:
	mkdir -p $(DESTDIR)$(swigdir)/perl5
	cp -a $(typefiles) $(DESTDIR)$(swigdir)/perl5
