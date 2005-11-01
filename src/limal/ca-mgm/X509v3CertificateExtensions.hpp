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
    class X509v3CertificateExtensions {
    public:
        X509v3CertificateExtensions(const X509v3CertificateExtensions& extensions);
        virtual ~X509v3CertificateExtensions();

        X509v3CertificateExtensions&
        operator=(const X509v3CertificateExtensions& extensions);

        NsBaseUrlExtension
        getNsBaseUrl() const;
        
        NsRevocationUrlExtension
        getNsRevocationUrl() const;
        
        NsCaRevocationUrlExtension
        getNsCaRevocationUrl() const;
        
        NsRenewalUrlExtension
        getNsRenewalUrl() const;
        
        NsCaPolicyUrlExtension
        getNsCaPolicyUrl() const;
        
        NsSslServerNameExtension
        getNsSslServerName() const;
        
        NsCommentExtension
        getNsComment() const;
        
        NsCertTypeExtension
        getNsCertType() const;
        
        KeyUsageExtension
        getKeyUsage() const;
        
        BasicConstraintsExtension
        getBasicConstraints() const;
        
        ExtendedKeyUsageExt
        getExtendedKeyUsage() const;
        
        SubjectKeyIdentifierExtension
        getSubjectKeyIdentifier() const;
        
        AuthorityKeyIdentifierExtension
        getAuthorityKeyIdentifier() const;
        
        SubjectAlternativeNameExtension
        getSubjectAlternativeName() const;
        
        IssuerAlternativeNameExtension
        getIssuerAlternativeName() const;
        
        AuthorityInfoAccessExtension
        getAuthorityInfoAccess() const;
        
        CRLDistributionPointsExtension
        getCRLDistributionPoints() const;
        
        CertificatePoliciesExtension
        getCertificatePolicies() const;
        
        virtual bool
        valid() const;
        
        virtual blocxx::StringArray
        verify() const;

        virtual blocxx::StringArray
        dump() const;

    protected:
        X509v3CertificateExtensions();
        /* String extensions */

        NsBaseUrlExtension              nsBaseUrl;
        NsRevocationUrlExtension        nsRevocationUrl;
        NsCaRevocationUrlExtension      nsCaRevocationUrl;
        NsRenewalUrlExtension           nsRenewalUrl;
        NsCaPolicyUrlExtension          nsCaPolicyUrl;
        NsSslServerNameExtension        nsSslServerName;
        NsCommentExtension              nsComment;

        /* Bit Strings */
        KeyUsageExtension               keyUsage; 
        NsCertTypeExtension             nsCertType;

        BasicConstraintsExtension       basicConstraints;
        ExtendedKeyUsageExt             extendedKeyUsage;
        SubjectKeyIdentifierExtension   subjectKeyIdentifier;
        AuthorityKeyIdentifierExtension authorityKeyIdentifier;
        SubjectAlternativeNameExtension subjectAlternativeName;
        IssuerAlternativeNameExtension  issuerAlternativeName;

        AuthorityInfoAccessExtension    authorityInfoAccess;
        CRLDistributionPointsExtension  crlDistributionPoints;
        CertificatePoliciesExtension    certificatePolicies;

    };

}
}

#endif // LIMAL_CA_MGM_X509V3_CERTIFICATE_EXTENSION_HPP
