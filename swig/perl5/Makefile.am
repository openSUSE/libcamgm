#
# Makefile.am for ca-mgm/swig/perl5
#

PERL        ?= perl
PERL_CC      = $(shell $(PERL) -MExtUtils::Embed -e ccopts)
PERL_LD      = $(shell $(PERL) -MExtUtils::Embed -e ldopts)
VENDOR_ARCH  = $(shell $(PERL) -MConfig -e 'print $$Config{installvendorarch};')

AM_CPPFLAGS  = -I$(top_builddir)/src -I$(top_srcdir)/src $(LIMAL_CFLAGS) $(PERL_CC) -Wno-unused -Wno-unused-parameter

# FIXME:
LIBS         = -L$(top_builddir)/src/.libs -Wl,-rpath,$(camgmlibdir) -lcamgm $(LIB_SSL) $(LIB_UTIL) $(LIB_PCRE) $(PERL_LD)

# FIXME:
CXXFLAGS    += -fPIC -DPIC
#AM_CPPFLAGS = $(DEBUG_FLAGS) -D_GNU_SOURCE -DLOCALEDIR=\"${localedir}\"
SWIGFLAGS    = -I${top_builddir}/typemaps/perl5 -I$(top_srcdir)/src -DCA_MGM_NAMESPACE=ca_mgm


# ========================================================


NAME    = CaMgm

sources = $(top_srcdir)/swig/$(NAME).i \
	  $(wildcard $(top_srcdir)/typemaps/perl5/*.i) \
	  $(wildcard $(top_srcdir)/src/ca-mgm/*.hpp) \
	  $(wildcard $(top_builddir)/src/ca-mgm/*.h)


# ========================================================


all: $(NAME).so

clean:
	rm -f *.o
	rm -f $(NAME).so
	rm -f *.cxx
	rm -f $(NAME).pm
	rm -fr auto

$(NAME).so: $(NAME)_wrap.o
	$(CXX) -shared -o $(NAME).so $< $(LDFLAGS) $(LIBS)
	@if test ! -d auto/$(NAME) ; then \
	    mkdir -p auto/$(NAME) ; \
        fi
	@if test ! -L auto/$(NAME)/$(NAME).so ; then \
            ln -s ../../$(NAME).so auto/$(NAME)/$(NAME).so ; \
        fi

$(NAME)_wrap.o: $(NAME)_wrap.cxx
	$(CXX) $(CXXFLAGS) $(AM_CPPFLAGS) -c $<

$(NAME)_wrap.cxx: $(sources)
	$(SWIG) -c++ -perl $(SWIGFLAGS) -o $(NAME)_wrap.cxx $<

install-data-local:
	mkdir -p $(DESTDIR)/$(VENDOR_ARCH)/auto/CaMgm
	install -m 644 $(NAME).pm $(DESTDIR)/$(VENDOR_ARCH)/
	install -m 755 $(NAME).so $(DESTDIR)/$(VENDOR_ARCH)/auto/CaMgm

