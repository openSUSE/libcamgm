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
	config.cpp \
	Utils.cpp  \
	ExtensionBase.cpp \
	LiteralValues.cpp \
	AuthorityInfoAccessExtension.cpp \
	X509v3CertificateExtensions_Priv.cpp \
	AuthorityKeyIdentifierExtension.cpp \
	AuthorityKeyIdentifierGenerateExtension.cpp \
	BasicConstraintsExtension.cpp \
	BitExtensions.cpp \
	ExtendedKeyUsageExt.cpp \
	CAConfig.cpp \
	CA.cpp \
	CertificateData.cpp \
	CertificateIssueData.cpp \
	CertificatePoliciesExtension.cpp \
	CRLData.cpp \
	CRLDistributionPointsExtension.cpp \
	CRLGenerationData.cpp \
	CRLReason.cpp \
	DNObject.cpp \
	IssuerAlternativeNameExtension.cpp \
	LocalManagement.cpp \
	RequestData.cpp \
	RequestGenerationData.cpp \
	StringExtensions.cpp \
	SubjectAlternativeNameExtension.cpp \
	SubjectKeyIdentifierExtension.cpp \
	X509v3CertificateExtensions.cpp \
	X509v3CertificateIssueExtensions.cpp \
	X509v3CRLExtensions.cpp \
	X509v3CRLGenerationExtensions.cpp \
	X509v3RequestExtensions.cpp \
	AuthorityKeyIdentifierExtension_Priv.cpp \
	CertificateData_Priv.cpp \
	CRLData_Priv.cpp \
	DNObject_Priv.cpp \
	RequestData_Priv.cpp \
	X509v3CRLExtensions_Priv.cpp \
	X509v3RequestExtensions_Priv.cpp \
	CRLReason_Priv.cpp \
	OpenSSLUtils.cpp \
	INIParser/IniFile.cpp   \
	INIParser/IniParser.cpp \
	INIParser/INIParser.cpp

liblimal_ca_mgm_la_CXXFLAGS = $(LIMAL_CFLAGS)

liblimal_ca_mgm_la_LDFLAGS  = \
	-version-info $(LIB_VERSION_INFO) \
	$(LIMAL_LIBS) -lssl

liblimal_ca_mgm_la_LIBADD = $(LIB_SSL)

CLEANFILES     = *~
DISTCLEANFILES = Commands.hpp
EXTRA_DIST     = *.hpp Commands.hpp.in openssl.cnf.tmpl \
                 INIParser/*.h INIParser/*.hpp

