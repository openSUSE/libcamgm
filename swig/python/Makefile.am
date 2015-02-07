#
# Makefile.am for ca-mgm/swig/ruby
#

PYCFLAGS = $(shell /usr/bin/python-config --cflags)
PYLDFLAGS = $(shell /usr/bin/python-config --ldflags)
SITE_ARCHDIR = $(shell python -c "from distutils.sysconfig import get_python_lib; print get_python_lib(plat_specific=True)")

AM_CPPFLAGS  = -I$(top_builddir)/src -I$(top_srcdir)/src $(LIMAL_CFLAGS) $(PYCFLAGS)
# FIXME:
LIBS         = -L$(top_builddir)/src/.libs -Wl,-rpath,$(camgmlibdir) -lcamgm $(LIB_SSL) $(LIB_UTIL) $(LIB_PCRE) $(PYLDFLAGS)

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


all: _$(NAME).so $(NAME).py $(NAME).pyc $(NAME).pyo

clean:
	rm -f *.o
	rm -f _$(NAME).so
	rm -f *.cxx
	rm -f $(NAME).py*

_$(NAME).so: $(NAME)_wrap.o
	$(CXX) -shared -o _$(NAME).so $< $(LDFLAGS) $(LIBS)

$(NAME)_wrap.o: $(NAME)_wrap.cxx
	$(CXX) $(CXXFLAGS) $(AM_CPPFLAGS) -c $<

$(NAME)_wrap.cxx: $(sources)
	$(SWIG) -c++ -python $(SWIGFLAGS) -o $(NAME)_wrap.cxx $<

$(NAME).py: _$(NAME).so

# default compile rules
%.pyc : %.py
	python -c "import compileall; compileall.compile_dir('./')"
%.pyo : %.py
	python -OO -c "import compileall; compileall.compile_dir('./')"

install-data-local:
	mkdir -p $(DESTDIR)/$(SITE_ARCHDIR)
	install -m 755 _$(NAME).so $(DESTDIR)/$(SITE_ARCHDIR)/
	install -m 644 $(NAME).py* $(DESTDIR)/$(SITE_ARCHDIR)/

