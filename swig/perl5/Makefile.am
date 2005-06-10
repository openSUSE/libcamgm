#
# Makefile.am for ca-mgm/swig/perl5
#

PERL        ?= perl
PERL_CC      = $(shell $(PERL) -MExtUtils::Embed -e ccopts)
PERL_LD      = $(shell $(PERL) -MExtUtils::Embed -e ldopts)
VENDOR_ARCH  = $(shell $(PERL) -MConfig -e 'print $$Config{installvendorarch};')

INCLUDES     = -I$(top_builddir)/src -I$(top_srcdir)/src $(LIMAL_CFLAGS) $(PERL_CC)

# FIXME:
LIBS         = -L$(top_builddir)/src/.libs -Wl,-rpath,$(limallibdir) -llimal-ca-mgm $(LIMAL_LIBS) $(PERL_LD)

# FIXME:
CXXFLAGS    += -Wno-unused -fPIC -DPIC
#AM_CPPFLAGS = $(DEBUG_FLAGS) -D_GNU_SOURCE -DLOCALEDIR=\"${localedir}\"
SWIGFLAGS    = -I$(top_srcdir)/src -DLIMAL_NAMESPACE=limal -DCA_MGM_NAMESPACE=ca_mgm


# ========================================================


NAME    = CaMgm

sources = $(top_srcdir)/swig/$(NAME).i \
	  $(wildcard $(top_srcdir)/src/limal/ca-mgm/*.hpp) \
	  $(wildcard $(top_builddir)/src/limal/ca-mgm/*.h)


# ========================================================


all: $(NAME).so

clean:
	rm -f *.o
	rm -f $(NAME).so
	rm -f *.cxx
	rm -f $(NAME).pm

$(NAME).so: $(NAME)_wrap.o
	$(CXX) -shared -o $(NAME).so $< $(LDFLAGS) $(LIBS)
	@if test ! -L auto; then \
	 ln -s . auto \
	; fi
	@if test ! -L LIMAL; then \
	 ln -s . LIMAL \
	; fi
	@if test ! -L $(NAME); then \
	 ln -s . $(NAME) \
	; fi

$(NAME)_wrap.o: $(NAME)_wrap.cxx
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $<

$(NAME)_wrap.cxx: $(sources)
	$(SWIG) -c++ -perl $(SWIGFLAGS) -o $(NAME)_wrap.cxx $<

install-data-local:
	mkdir -p $(DESTDIR)/$(VENDOR_ARCH)/auto/LIMAL/CaMgm
	mkdir -p $(DESTDIR)/$(VENDOR_ARCH)/LIMAL/
	install -m 644 $(NAME).pm $(DESTDIR)/$(VENDOR_ARCH)/LIMAL/
	install -m 644 $(NAME).so $(DESTDIR)/$(VENDOR_ARCH)/auto/LIMAL/CaMgm

