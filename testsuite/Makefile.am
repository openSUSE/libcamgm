#
# Makefile.am for limal-ca-mgm/testsuite
#
SUBDIRS = lib config limal.test single.out
PACKAGE = limal
AUTOMAKE_OPTIONS = dejagnu

INCLUDES= -I. -I$(top_srcdir)/src

AM_CPPFLAGS = 

AM_LDFLAGS = \
	-Xlinker --whole-archive \
	$(top_builddir)/src/liblimal-ca-mgm.la \
	-Xlinker --no-whole-archive

noinst_PROGRAMS = CAConfig.single CA1.single CA2.multi \
				  CA3.multi CA4.multi

CAConfig_single_SOURCES = CAConfig.cc

CA1_single_SOURCES = CA1.cc

CA2_multi_SOURCES = CA2.cc

CA3_multi_SOURCES = CA3.cc

CA4_multi_SOURCES = CA4.cc

clean-local:
	rm -f tmp.err.* tmp.out.* site.exp site.bak

EXTRA_DIST = test_multi/*.in test_multi/*.out test_multi/*.err \
			 perl_test/*.in perl_test/*.out perl_test/*.err \
			 TestRepos/* CA2/*.* CA3/*.* CA4/*.*
