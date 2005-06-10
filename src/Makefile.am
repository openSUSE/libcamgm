#
# Makefile.am for limal-ca-mgm/src
#

SUBDIRS = limal

INCLUDES = -I. -I$(srcdir)

# FIXME:
AM_CPPFLAGS = $(DEBUG_FLAGS) -pthread -DLOCALEDIR=\"${localedir}\"
AM_LDFLAGS  = -pthread

limallib_LTLIBRARIES = liblimal-ca-mgm.la

liblimal_ca_mgm_la_SOURCES  =	\
	CaMgm.cpp		\
	config.cpp

liblimal_ca_mgm_la_CXXFLAGS = $(LIMAL_CFLAGS)

liblimal_ca_mgm_la_LDFLAGS  = \
	-version-info $(LIB_VERSION_INFO) \
	$(LIMAL_LIBS)

