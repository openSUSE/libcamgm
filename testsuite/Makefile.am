#
# Makefile.am for limal-ca-mgm/testsuite
#
SUBDIRS = TestRepos lib config limal.test single.out
PACKAGE = limal
AUTOMAKE_OPTIONS = dejagnu

INCLUDES= -I. -I$(top_srcdir)/src

AM_CPPFLAGS = $(DEBUG_FLAGS) -pthread -DLOCALEDIR=\"${localedir}\" $(PERL_CFLAGS)

AM_LDFLAGS = \
	-pthread -Xlinker --whole-archive -lssl \
	$(top_builddir)/src/liblimal-ca-mgm.la \
	-Xlinker --no-whole-archive $(PERL_LDFLAGS)

noinst_PROGRAMS = CAConfig.single CA1.single CA2.multi \
                  CA3.multi CA4.multi  \
                  CA5.multi CA6.multi CA7.multi CA8.single \
                  CA9.single CertificateTest.single \
                  CertificateTest2.single RevokeTest.single \
                  RevokeTest2.single RevokeTest3.single \
                  RevokeTest4.single UpdateDBTest.single \
                  ListTest.single SubCATest.single \
                  RemoveRequestTest.single RevxRemoveCertificateTest.single \
                  VerifyTest.single ParseCATest.single \
                  CertificateTest3.single ParseCertificateTest.multi \
                  ParseRequestTest.multi ParseCRLTest.multi \
                  RevokeTest5.single ImportRequestTest.single \
                  DeleteCATest.single ImportCATest.single

CAConfig_single_SOURCES = CAConfig.cc

CA1_single_SOURCES = CA1.cc

CA2_multi_SOURCES = CA2.cc

CA3_multi_SOURCES = CA3.cc

CA4_multi_SOURCES = CA4.cc

CA5_multi_SOURCES = CA5.cc

CA6_multi_SOURCES = CA6.cc

CA7_multi_SOURCES = CA7.cc

CA8_single_SOURCES = CA8.cc perlxsi.cpp

CA9_single_SOURCES = CA9.cc perlxsi.cpp

CertificateTest_single_SOURCES = CertificateTest.cc perlxsi.cpp

CertificateTest2_single_SOURCES = CertificateTest2.cc perlxsi.cpp

CertificateTest3_single_SOURCES = CertificateTest3.cc perlxsi.cpp

RevokeTest_single_SOURCES = RevokeTest.cc perlxsi.cpp

RevokeTest2_single_SOURCES = RevokeTest2.cc perlxsi.cpp

RevokeTest3_single_SOURCES = RevokeTest3.cc perlxsi.cpp

RevokeTest4_single_SOURCES = RevokeTest4.cc perlxsi.cpp

RevokeTest5_single_SOURCES = RevokeTest5.cc perlxsi.cpp

UpdateDBTest_single_SOURCES = UpdateDBTest.cc perlxsi.cpp

ListTest_single_SOURCES = ListTest.cc perlxsi.cpp

SubCATest_single_SOURCES = SubCATest.cc perlxsi.cpp

RemoveRequestTest_single_SOURCES = RemoveRequestTest.cc perlxsi.cpp

RevxRemoveCertificateTest_single_SOURCES = RemoveCertificateTest.cc perlxsi.cpp

VerifyTest_single_SOURCES = VerifyTest.cc perlxsi.cpp

ParseCATest_single_SOURCES = ParseCATest.cc perlxsi.cpp

ParseCertificateTest_multi_SOURCES = ParseCertificateTest.cc perlxsi.cpp

ParseRequestTest_multi_SOURCES = ParseRequestTest.cc perlxsi.cpp

ParseCRLTest_multi_SOURCES = ParseCRLTest.cc perlxsi.cpp

ImportRequestTest_single_SOURCES = ImportRequestTest.cc perlxsi.cpp

DeleteCATest_single_SOURCES = DeleteCATest.cc perlxsi.cpp

ImportCATest_single_SOURCES = ImportCATest.cc perlxsi.cpp

clean-local:
	rm -f tmp.err.* tmp.out.* site.exp site.bak openssl.cnf.tmpl.test
	rm -f *~ perlxsi.cpp
	rm -rf CA2/out
	rm -rf CA3/out
	rm -rf CA4/out
	rm -rf CA5/out
	rm -rf CA6/out
	rm -rf CA7/out
	rm -rf single.out/out
	rm -rf ParseCertificateTest/out
	rm -rf ParseRequestTest/out
	rm -rf ParseCRLTest/out

perlxsi.cpp:
	perl -MExtUtils::Embed -e xsinit -- -o $@

EXTRA_DIST = test_multi/*.in test_multi/*.out test_multi/*.err \
             perl_test/*.in perl_test/*.out perl_test/*.err \
             CA2/*.* CA3/*.* CA4/*.* CA5/*.* \
             CA6/*.* CA7/*.* ParseCertificateTest/*.* \
             ParseRequestTest/*.* ParseCRLTest/*.*
