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
	ExtensionBase.cpp \
	AuthorityInfoAccessExtension.cpp \
	AuthorityKeyIdentifierExtension.cpp \
	AuthorityKeyIdentifierGenerateExtension.cpp \
	BasicConstraintsExtension.cpp \
	BitExtensions.cpp \
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
	LiteralValues.cpp \
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
	X509v3CertificateExtensions_Priv.cpp \
	X509v3CRLExtensions_Priv.cpp \
	X509v3RequestExtensions_Priv.cpp \
    CRLReason_Priv.cpp \
    OpenSSLUtils.cpp

liblimal_ca_mgm_la_CXXFLAGS = $(LIMAL_CFLAGS)

liblimal_ca_mgm_la_LDFLAGS  = \
	-version-info $(LIB_VERSION_INFO) \
	$(LIMAL_LIBS)

CLEANFILES = *~
