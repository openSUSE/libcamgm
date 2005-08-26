/*---------------------------------------------------------------------\
|                                                                      |
|                     _     _   _   _     __     _                     |
|                    | |   | | | \_/ |   /  \   | |                    |
|                    | |   | | | |_| |  / /\ \  | |                    |
|                    | |__ | | | | | | / ____ \ | |__                  |
|                    |____||_| |_| |_|/ /    \ \|____|                 |
|                                                                      |
|                             ca-mgm library                           |
|                                                                      |
|                                         (C) SUSE Linux Products GmbH |
\----------------------------------------------------------------------/

  File:       X509v3CertificateExtensions_Priv.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_X509V3_CERTIFICATE_EXTENSION_PRIV_HPP
#define    LIMAL_CA_MGM_X509V3_CERTIFICATE_EXTENSION_PRIV_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/X509v3CertificateExtensions.hpp>
#include  <openssl/x509.h>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class X509v3CertificateExtensions_Priv : public X509v3CertificateExtensions {
    public:
        X509v3CertificateExtensions_Priv();
        X509v3CertificateExtensions_Priv(STACK_OF(X509_EXTENSION) *extensions);
        X509v3CertificateExtensions_Priv(const X509v3CertificateExtensions_Priv& extensions);
        virtual ~X509v3CertificateExtensions_Priv();

        void   setNsBaseUrl(const NsBaseUrlExtension &ext);
        void   setNsRevocationUrl(const NsRevocationUrlExtension &ext);
        void   setNsCaRevocationUrl(const NsCaRevocationUrlExtension &ext);
        void   setNsRenewalUrl(const NsRenewalUrlExtension &ext);
        void   setNsCaPolicyUrl(const NsCaPolicyUrlExtension &ext);
        void   setNsSslServerName(const NsSslServerNameExtension &ext);
        void   setNsComment(const NsCommentExtension &ext);
        void   setNsCertType(const NsCertTypeExtension &ext);
        void   setKeyUsage(const KeyUsageExtension &ext);
        void   setBasicConstraints(const BasicConstraintsExtension &ext);
        void   setExtendedKeyUsage(const ExtendedKeyUsageExtension &ext);
        void   setSubjectKeyIdentifier(const SubjectKeyIdentifierExtension &ext);
        void   setAuthorityKeyIdentifier(const AuthorityKeyIdentifierExtension &ext);
        void   setSubjectAlternativeName(const SubjectAlternativeNameExtension &ext);
        void   setIssuerAlternativeName(const IssuerAlternativeNameExtension &ext);
        void   setAuthorityInfoAccess(const AuthorityInfoAccessExtension &ext);
        void   setCRLDistributionPoints(const CRLDistributionPointsExtension &ext);
        void   setCertificatePolicies(const CertificatePoliciesExtension &ext);

    private:

        X509v3CertificateExtensions_Priv& operator=(const X509v3CertificateExtensions_Priv& extensions);

        void parseStringExtension(STACK_OF(X509_EXTENSION)* cert, int nid, StringExtension &ext);

        void parseBitExtension(STACK_OF(X509_EXTENSION)* cert, int nid, BitExtension &ext);

        void parseExtKeyUsageExtension(STACK_OF(X509_EXTENSION)* cert, ExtendedKeyUsageExtension &ext);

        void parseBasicConstraintsExtension(STACK_OF(X509_EXTENSION)* cert, BasicConstraintsExtension &ext);

        void parseSubjectKeyIdentifierExtension(STACK_OF(X509_EXTENSION) *cert,
                                                SubjectKeyIdentifierExtension &ext);

        void parseSubjectAlternativeNameExtension(STACK_OF(X509_EXTENSION) *cert,
                                                  SubjectAlternativeNameExtension &ext);

        void parseIssuerAlternativeNameExtension(STACK_OF(X509_EXTENSION) *cert,
                                                 IssuerAlternativeNameExtension &ext);

        void parseCRLDistributionPointsExtension(STACK_OF(X509_EXTENSION) *cert,
                                                 CRLDistributionPointsExtension &ext);

        void parseAuthorityInfoAccessExtension(STACK_OF(X509_EXTENSION) *cert,
                                               AuthorityInfoAccessExtension &ext);

        void parseCertificatePoliciesExtension(STACK_OF(X509_EXTENSION) *cert,
                                               CertificatePoliciesExtension &ext);


    };

}
}

#endif // LIMAL_CA_MGM_X509V3_CERTIFICATE_EXTENSION_PRIV_HPP
