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

  File:       X509v3CertificateExtensions.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_X509V3_CERTIFICATE_EXTENSION_HPP
#define    LIMAL_CA_MGM_X509V3_CERTIFICATE_EXTENSION_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/StringExtensions.hpp>
#include  <limal/ca-mgm/BitExtensions.hpp>
#include  <limal/ca-mgm/ExtendedKeyUsageExt.hpp>
#include  <limal/ca-mgm/BasicConstraintsExtension.hpp>
#include  <limal/ca-mgm/SubjectKeyIdentifierExtension.hpp>
#include  <limal/ca-mgm/SubjectKeyIdentifierExtension.hpp>
#include  <limal/ca-mgm/AuthorityKeyIdentifierExtension.hpp>
#include  <limal/ca-mgm/SubjectAlternativeNameExtension.hpp>
#include  <limal/ca-mgm/IssuerAlternativeNameExtension.hpp>
#include  <limal/ca-mgm/AuthorityInfoAccessExtension.hpp>
#include  <limal/ca-mgm/CRLDistributionPointsExtension.hpp>
#include  <limal/ca-mgm/CertificatePoliciesExtension.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    /**
     * @brief Read-only data representation of X509 V3 Certificate Extensions
     */
    class X509v3CertificateExts {
    public:
        X509v3CertificateExts(const X509v3CertificateExts& extensions);
        virtual ~X509v3CertificateExts();

        X509v3CertificateExts&
        operator=(const X509v3CertificateExts& extensions);

        NsBaseUrlExt
        getNsBaseUrl() const;
        
        NsRevocationUrlExt
        getNsRevocationUrl() const;
        
        NsCaRevocationUrlExt
        getNsCaRevocationUrl() const;
        
        NsRenewalUrlExt
        getNsRenewalUrl() const;
        
        NsCaPolicyUrlExt
        getNsCaPolicyUrl() const;
        
        NsSslServerNameExt
        getNsSslServerName() const;
        
        NsCommentExt
        getNsComment() const;
        
        NsCertTypeExt
        getNsCertType() const;
        
        KeyUsageExt
        getKeyUsage() const;
        
        BasicConstraintsExt
        getBasicConstraints() const;
        
        ExtendedKeyUsageExt
        getExtendedKeyUsage() const;
        
        SubjectKeyIdentifierExt
        getSubjectKeyIdentifier() const;
        
        AuthorityKeyIdentifierExt
        getAuthorityKeyIdentifier() const;
        
        SubjectAlternativeNameExt
        getSubjectAlternativeName() const;
        
        IssuerAlternativeNameExt
        getIssuerAlternativeName() const;
        
        AuthorityInfoAccessExt
        getAuthorityInfoAccess() const;
        
        CRLDistributionPointsExt
        getCRLDistributionPoints() const;
        
        CertificatePoliciesExt
        getCertificatePolicies() const;
        
        virtual bool
        valid() const;
        
        virtual blocxx::StringArray
        verify() const;

        virtual blocxx::StringArray
        dump() const;

    protected:
        X509v3CertificateExts();
        /* String extensions */

        NsBaseUrlExt              nsBaseUrl;
        NsRevocationUrlExt        nsRevocationUrl;
        NsCaRevocationUrlExt      nsCaRevocationUrl;
        NsRenewalUrlExt           nsRenewalUrl;
        NsCaPolicyUrlExt          nsCaPolicyUrl;
        NsSslServerNameExt        nsSslServerName;
        NsCommentExt              nsComment;

        /* Bit Strings */
        KeyUsageExt               keyUsage; 
        NsCertTypeExt             nsCertType;

        BasicConstraintsExt       basicConstraints;
        ExtendedKeyUsageExt       extendedKeyUsage;
        SubjectKeyIdentifierExt   subjectKeyIdentifier;
        AuthorityKeyIdentifierExt authorityKeyIdentifier;
        SubjectAlternativeNameExt subjectAlternativeName;
        IssuerAlternativeNameExt  issuerAlternativeName;

        AuthorityInfoAccessExt    authorityInfoAccess;
        CRLDistributionPointsExt  crlDistributionPoints;
        CertificatePoliciesExt    certificatePolicies;

    };

}
}

#endif // LIMAL_CA_MGM_X509V3_CERTIFICATE_EXTENSION_HPP
