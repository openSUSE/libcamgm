#
# Makefile.am for limal-ca-mgm/src
#

SUBDIRS = limal

INCLUDES = -I. -I$(srcdir)

# FIXME:
AM_CPPFLAGS = $(DEBUG_FLAGS) -pthread -DLOCALEDIR=\"${localedir}\"
AM_LDFLAGS  = -pthread

camgmlib_LTLIBRARIES = libcamgm.la

libcamgm_la_SOURCES  =	\
        Date.cpp                \
        PerlRegEx.cpp           \
        PosixRegEx.cpp          \
        String.cpp              \
        ReferenceCounted.cpp    \
        ValuePosixRECheck.cpp   \
        ValuePerlRECheck.cpp    \
        ValueIntCheck.cpp       \
        ValueCheck.cpp          \
        Exception.cpp           \
        LogControl.cpp          \
        PathName.cpp            \
        PathInfo.cpp            \
        PathUtils.cpp           \
        ByteBuffer.cpp          \
        LDAPUrlImpl.cpp         \
        UrlByScheme.cpp         \
        UrlUtils.cpp            \
        UrlBase.cpp             \
        Url.cpp                 \
        Utils.cpp \
	config.cpp \
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
	LiteralValues_Priv.cpp \
	OpenSSLUtils.cpp \
	INIParser/IniFile.cpp   \
	INIParser/IniParser.cpp \
	INIParser/INIParser.cpp \
	ExternalProgram.cpp \
	ExternalDataSource.cpp

#        config.cpp              \
libcamgm_la_CXXFLAGS = $(LIMAL_CFLAGS)

libcamgm_la_LDFLAGS  = \
	-version-info $(LIB_VERSION_INFO) \
	$(LIMAL_LIBS) -lssl

libcamgm_la_LIBADD = $(LIB_SSL) $(LIB_UTIL) $(LIB_PCRE)

CLEANFILES     = *~
DISTCLEANFILES = Commands.hpp config.log
EXTRA_DIST     = *.hpp Commands.hpp.in openssl.cnf.tmpl \
                 INIParser/*.h INIParser/*.hpp

