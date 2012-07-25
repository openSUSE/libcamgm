#
# Makefile.am for ca-mgm/swig/ruby
#

RUBY_PC        = $(shell ruby -r rbconfig -e "print RbConfig::CONFIG[\"ruby_pc\"][0..-4]")
RUBY_INCLUDE   = $(shell pkg-config --cflags $(RUBY_PC))
VENDOR_ARCHDIR = $(shell ruby -r rbconfig -e "print Config::CONFIG['vendorarchdir']")
RUBY_LIB       = -lruby

INCLUDES       = -I$(top_builddir)/src -I$(top_srcdir)/src $(LIMAL_CFLAGS) $(RUBY_INCLUDE)
# FIXME:
LIBS         = -L$(top_builddir)/src/.libs -Wl,-rpath,$(camgmlibdir) -lcamgm $(LIB_SSL) $(LIB_UTIL) $(LIB_PCRE) $(PERL_LD) $(RUBY_LIB)

# FIXME:
CXXFLAGS    += -Wno-unused -fPIC -DPIC
#AM_CPPFLAGS = $(DEBUG_FLAGS) -D_GNU_SOURCE -DLOCALEDIR=\"${localedir}\"
SWIGFLAGS    = -I${top_builddir}/typemaps -I$(top_srcdir)/src -DCA_MGM_NAMESPACE=ca_mgm


# ========================================================


NAME    = CaMgm

sources = $(top_srcdir)/swig/$(NAME).i \
	  $(wildcard $(top_srcdir)/src/ca-mgm/*.hpp) \
	  $(wildcard $(top_builddir)/src/ca-mgm/*.h)


# ========================================================


all: $(NAME).so

clean:
	rm -f *.o
	rm -f $(NAME).so
	rm -f *.cxx
	rm -f $(NAME).rb

$(NAME).so: $(NAME)_wrap.o
	$(CXX) -shared -o $(NAME).so $< $(LDFLAGS) $(LIBS)

$(NAME)_wrap.o: $(NAME)_wrap.cxx
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $<

$(NAME)_wrap.cxx: $(sources)
	$(SWIG) -c++ -ruby $(SWIGFLAGS) -o $(NAME)_wrap.cxx $<

install-data-local:
	mkdir -p $(DESTDIR)/$(VENDOR_ARCHDIR)
	install -m 755 $(NAME).so $(DESTDIR)/$(VENDOR_ARCHDIR)/

