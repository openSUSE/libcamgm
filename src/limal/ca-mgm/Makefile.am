#
# Makefile.am for limal-ca-mgm/src/limal/ca-mgm
#

pkgcamgmincludedir = $(camgmincludedir)/ca-mgm

# these go to $(pkglimalincludedir)
pkgcamgminclude_HEADERS =   \
	config.h \
        AuthorityInfoAccessExtension.hpp \
        AuthorityKeyIdentifierExtension.hpp \
        AuthorityKeyIdentifierGenerateExtension.hpp \
        BasicConstraintsExtension.hpp \
        BitExtensions.hpp \
        ExtendedKeyUsageExt.hpp \
        CAConfig.hpp \
        CA.hpp \
        CertificateData.hpp \
        CertificateIssueData.hpp \
        CertificatePoliciesExtension.hpp \
        CommonData.hpp \
        CRLData.hpp \
        CRLDistributionPointsExtension.hpp \
        CRLGenerationData.hpp \
        CRLReason.hpp \
        DNObject.hpp \
        ExtensionBase.hpp \
        IssuerAlternativeNameExtension.hpp \
        LiteralValues.hpp \
        LocalManagement.hpp \
        RequestData.hpp \
        RequestGenerationData.hpp \
        StringExtensions.hpp \
        SubjectAlternativeNameExtension.hpp \
        SubjectKeyIdentifierExtension.hpp \
        X509v3CertificateExtensions.hpp \
        X509v3CertificateIssueExtensions.hpp \
        X509v3CRLExtensions.hpp \
        X509v3CRLGenerationExtensions.hpp \
        X509v3RequestExtensions.hpp 


#
# replace some constants only
#
config.h.in: Makefile
config.h: config.h.in
	$(top_builddir)/config.status --file=$@:$<

EXTRA_DIST = config.h.in
DISTCLEANFILES = config.h
CLEANFILES = *~
