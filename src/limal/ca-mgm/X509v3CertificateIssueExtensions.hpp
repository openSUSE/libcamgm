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

  File:       X509v3CertificateIssueExtensions.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#ifndef    LIMAL_CA_MGM_X509V_CERTIFICATE_ISSUE_EXTENSIONS_HPP
#define    LIMAL_CA_MGM_X509V_CERTIFICATE_ISSUE_EXTENSIONS_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/StringExtensions.hpp>
#include  <limal/ca-mgm/BitExtensions.hpp>
#include  <limal/ca-mgm/BasicConstraintsExtension.hpp>
#include  <limal/ca-mgm/SubjectKeyIdentifierExtension.hpp>
#include  <limal/ca-mgm/SubjectKeyIdentifierExtension.hpp>
#include  <limal/ca-mgm/AuthorityKeyIdentifierGenerateExtension.hpp>
#include  <limal/ca-mgm/SubjectAlternativeNameExtension.hpp>
#include  <limal/ca-mgm/IssuerAlternativeNameExtension.hpp>
#include  <limal/ca-mgm/AuthorityInfoAccessExtension.hpp>
#include  <limal/ca-mgm/CRLDistributionPointsExtension.hpp>
#include  <limal/ca-mgm/CertificatePoliciesExtension.hpp>

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

    class CA;

    /**
     * @brief Collection of X509v3 extension for signing a certificate
     *
     * This class includes a collection of X509v3 extension for signing a certificate
     */
    class X509v3CertificateIssueExtensions {
    public:
        X509v3CertificateIssueExtensions();
        X509v3CertificateIssueExtensions(CA& ca, Type type);
        X509v3CertificateIssueExtensions(const X509v3CertificateIssueExtensions& extensions);
        virtual ~X509v3CertificateIssueExtensions();

        X509v3CertificateIssueExtensions& operator=(const X509v3CertificateIssueExtensions& extensions);

        void                            setNsBaseUrl(const NsBaseUrlExtension &ext);
        NsBaseUrlExtension              getNsBaseUrl() const;

        void                            setNsRevocationUrl(const NsRevocationUrlExtension &ext);
        NsRevocationUrlExtension        getNsRevocationUrl() const;

        void                            setNsCaRevocationUrl(const NsCaRevocationUrlExtension &ext);
        NsCaRevocationUrlExtension      getNsCaRevocationUrl() const;

        void                            setNsRenewalUrl(const NsRenewalUrlExtension &ext);
        NsRenewalUrlExtension           getNsRenewalUrl() const;

        void                            setNsCaPolicyUrl(const NsCaPolicyUrlExtension &ext);
        NsCaPolicyUrlExtension          getNsCaPolicyUrl();

        void                            setNsSslServerName(const NsSslServerNameExtension &ext);
        NsSslServerNameExtension        getNsSslServerName() const;

        void                            setNsComment(const NsCommentExtension &ext);
        NsCommentExtension              getNsComment() const;

        void                            setNsCertType(const NsCertTypeExtension &ext);
        NsCertTypeExtension             getNsCertType() const;

        void                            setKeyUsage(const KeyUsageExtension &ext);
        KeyUsageExtension               getKeyUsage();

        void                            setBasicConstraints(const BasicConstraintsExtension &ext);
        BasicConstraintsExtension       getBasicConstraints() const;

        void                            setExtendedKeyUsage(const ExtendedKeyUsageExtension &ext);
        ExtendedKeyUsageExtension       getExtendedKeyUsage() const;

        void                            setSubjectKeyIdentifier(const SubjectKeyIdentifierExtension &ext);
        SubjectKeyIdentifierExtension   getSubjectKeyIdentifier() const;

        void                            setAuthorityKeyIdentifier(const AuthorityKeyIdentifierGenerateExtension &ext);
        AuthorityKeyIdentifierGenerateExtension getAuthorityKeyIdentifier() const;

        void                            setSubjectAlternativeName(const SubjectAlternativeNameExtension &ext);
        SubjectAlternativeNameExtension getSubjectAlternativeName() const;
        
        void                            setIssuerAlternativeName(const IssuerAlternativeNameExtension &ext);
        IssuerAlternativeNameExtension  getIssuerAlternativeName() const;
                                                                     
        void                            setAuthorityInfoAccess(const AuthorityInfoAccessExtension &ext);
        AuthorityInfoAccessExtension    getAuthorityInfoAccess() const;

        void                            setCRLDistributionPoints(const CRLDistributionPointsExtension &ext);
        CRLDistributionPointsExtension  getCRLDistributionPoints() const;

        void                            setCertificatePolicies(const CertificatePoliciesExtension &ext);
        CertificatePoliciesExtension    getCertificatePolicies() const;

        void                            commit2Config(CA& ca, Type type) const;

        virtual bool                    valid() const;
        virtual blocxx::StringArray     verify() const;

        virtual blocxx::StringArray  dump() const;

    private:
        /* String extensions */

        NsBaseUrlExtension                      nsBaseUrl;
        NsRevocationUrlExtension                nsRevocationUrl;
        NsCaRevocationUrlExtension              nsCaRevocationUrl;
        NsRenewalUrlExtension                   nsRenewalUrl;
        NsCaPolicyUrlExtension                  nsCaPolicyUrl;
        NsSslServerNameExtension                nsSslServerName;
        NsCommentExtension                      nsComment;

        /* Bit Strings */
        KeyUsageExtension                       keyUsage;
        NsCertTypeExtension                     nsCertType;

        BasicConstraintsExtension               basicConstraints;
        ExtendedKeyUsageExtension               extendedKeyUsage;
        SubjectKeyIdentifierExtension           subjectKeyIdentifier;
        AuthorityKeyIdentifierGenerateExtension authorityKeyIdentifier;
        SubjectAlternativeNameExtension         subjectAlternativeName;
        IssuerAlternativeNameExtension          issuerAlternativeName;

        AuthorityInfoAccessExtension            authorityInfoAccess;
        CRLDistributionPointsExtension          crlDistributionPoints;
        CertificatePoliciesExtension            certificatePolicies;

    };

}
}

#endif // LIMAL_CA_MGM_X509V_CERTIFICATE_ISSUE_EXTENSIONS_HPP
