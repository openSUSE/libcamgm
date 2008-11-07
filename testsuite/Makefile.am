#
# Makefile.am for limal-ca-mgm/testsuite
#
SUBDIRS = TestRepos lib config limal.test single.out
PACKAGE = limal
AUTOMAKE_OPTIONS = dejagnu

INCLUDES= -I. -I$(top_srcdir)/src

AM_CPPFLAGS = $(DEBUG_FLAGS) -pthread -DLOCALEDIR=\"${localedir}\" 

AM_LDFLAGS = \
	-pthread -Xlinker --whole-archive \
	$(top_builddir)/src/liblimal-ca-mgm.la \
	-Xlinker --no-whole-archive 

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
                  CertificateTest3.single CertificateTest4.single \
		  CertificateTest5.single ParseCertificateTest.multi \
                  ParseCertificateTest2.multi ParseRequestTest.multi ParseCRLTest.multi \
                  RevokeTest5.single ImportRequestTest.single \
                  DeleteCATest.single ImportCATest.single \
                  X_ListCATreeTest.single ExportTest.single \
                  ImportCommonCertificateTest.single \
                  ConvertTest.single iniParser.multi \
                  sysConfig.single RequestTest.single \
                  CRLTest.single IPv6CheckTest.single

CAConfig_single_SOURCES = CAConfig.cc

CA1_single_SOURCES = CA1.cc

CA2_multi_SOURCES = CA2.cc

CA3_multi_SOURCES = CA3.cc

CA4_multi_SOURCES = CA4.cc

CA5_multi_SOURCES = CA5.cc

CA6_multi_SOURCES = CA6.cc

CA7_multi_SOURCES = CA7.cc

CA8_single_SOURCES = CA8.cc

CA9_single_SOURCES = CA9.cc

CertificateTest_single_SOURCES = CertificateTest.cc

CertificateTest2_single_SOURCES = CertificateTest2.cc

CertificateTest3_single_SOURCES = CertificateTest3.cc

CertificateTest4_single_SOURCES = CertificateTest4.cc

CertificateTest5_single_SOURCES = CertificateTest5.cc

RevokeTest_single_SOURCES = RevokeTest.cc 

RevokeTest2_single_SOURCES = RevokeTest2.cc 

RevokeTest3_single_SOURCES = RevokeTest3.cc 

RevokeTest4_single_SOURCES = RevokeTest4.cc

RevokeTest5_single_SOURCES = RevokeTest5.cc 

UpdateDBTest_single_SOURCES = UpdateDBTest.cc 

ListTest_single_SOURCES = ListTest.cc

SubCATest_single_SOURCES = SubCATest.cc

RemoveRequestTest_single_SOURCES = RemoveRequestTest.cc

RevxRemoveCertificateTest_single_SOURCES = RemoveCertificateTest.cc

VerifyTest_single_SOURCES = VerifyTest.cc

ParseCATest_single_SOURCES = ParseCATest.cc

ParseCertificateTest_multi_SOURCES = ParseCertificateTest.cc

ParseCertificateTest2_multi_SOURCES = ParseCertificateTest2.cc

ParseRequestTest_multi_SOURCES = ParseRequestTest.cc

ParseCRLTest_multi_SOURCES = ParseCRLTest.cc

ImportRequestTest_single_SOURCES = ImportRequestTest.cc

DeleteCATest_single_SOURCES = DeleteCATest.cc

ImportCATest_single_SOURCES = ImportCATest.cc 

X_ListCATreeTest_single_SOURCES = ListCATreeTest.cc

ExportTest_single_SOURCES = ExportTest.cc

ImportCommonCertificateTest_single_SOURCES = ImportCommonCertificateTest.cc

ConvertTest_single_SOURCES = ConvertTest.cc

iniParser_multi_SOURCES = iniParser.cc

sysConfig_single_SOURCES = sysConfig.cc

RequestTest_single_SOURCES = RequestTest.cc

CRLTest_single_SOURCES = CRLTest.cc

IPv6CheckTest_single_SOURCES = IPv6CheckTest.cc

clean-local:
	rm -f tmp.err.* tmp.out.* site.exp site.bak openssl.cnf.tmpl.test
	rm -f *~ limal.log limal.sum .rnd
	rm -rf CA2/out
	rm -rf CA3/out
	rm -rf CA4/out
	rm -rf CA5/out
	rm -rf CA6/out
	rm -rf CA7/out
	rm -rf single.out/out
	rm -rf ParseCertificateTest/out
	rm -rf ParseCertificateTest2/out
	rm -rf ParseRequestTest/out
	rm -rf ParseCRLTest/out
	rm -f CA2/*~
	rm -f CA3/*~
	rm -f CA4/*~
	rm -f CA5/*~
	rm -f CA6/*~
	rm -f CA7/*~
	rm -f single.out/*~
	rm -f ParseCertificateTest/*~
	rm -f ParseRequestTest/*~
	rm -f ParseCRLTest/*~

EXTRA_DIST = CA2/*.* CA3/*.* CA4/*.* CA5/*.* single.out/*.* \
             CA6/*.* CA7/*.* ParseCertificateTest/*.*       \
             ParseCertificateTest2/*.*                      \
             ParseRequestTest/*.* ParseCRLTest/*.*          \
             TestRepos2/Test_CA3/*.*                        \
             TestRepos2/Test_CA3/crl/*.*                    \
             TestRepos3/My_Test_SuSE_CA/*.*                 \
             TestRepos3/openssl.cnf.tmpl                    \
             TestRepos3/SUSEIPsecCA/*.*                     \
             TestRepos3/SUSERootCA/*/*.*                    \
             TestRepos3/SUSERootCA/*.*                      \
             TestRepos3/SUSEUserCA/*/*.*                    \
             TestRepos3/SUSEUserCA/*.*                      \
             TestRepos3/Test1_SuSE_CA/*/*.*                 \
             TestRepos3/Test1_SuSE_CA/*.*                   \
             TestRepos3/Test2_SuSE_CA/*/*.*                 \
             TestRepos3/Test2_SuSE_CA/*.*                   \
             TestRepos3/Test3_SuSE_CA/*.*                   \
             TestRepos3/.cas/*.*                            \
             TestRepos3/testuser.pem                        \
             TestRepos3/windows-ca.crt                      \
             TestRepos3/windows-client.crt                  \
             TestRepos3/windows-kdc.crt                     \
             TestRepos3/edir-cert.pem                       \
             openssl.cnf.tmpl                               \
             perl-*.single                                  \
             iniParser/*.out iniParser/*.in                 \
             iniParser/*.ini iniParser/*.err

