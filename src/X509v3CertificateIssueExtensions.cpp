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

  File:       X509v3CertificateIssueExtensions.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/


#include  <limal/ca-mgm/X509v3CertificateIssueExtensions.hpp>

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

X509v3CertificateIssueExtensions::X509v3CertificateIssueExtensions()
{
}

X509v3CertificateIssueExtensions::X509v3CertificateIssueExtensions(CA& ca, Type type)
{
}

X509v3CertificateIssueExtensions::X509v3CertificateIssueExtensions(const X509v3CertificateIssueExtensions& extensions)
{
}

X509v3CertificateIssueExtensions::~X509v3CertificateIssueExtensions()
{
}

X509v3CertificateIssueExtensions&
X509v3CertificateIssueExtensions::operator=(const X509v3CertificateIssueExtensions& extensions)
{
    return *this;
}

void
X509v3CertificateIssueExtensions::setNsBaseUrl(const NsBaseUrlExtension &ext)
{
    nsBaseUrl = ext;
}

NsBaseUrlExtension
X509v3CertificateIssueExtensions::getNsBaseUrl() const
{
    return nsBaseUrl;
}

void
X509v3CertificateIssueExtensions::setNsRevocationUrl(const NsRevocationUrlExtension &ext)
{
    nsRevocationUrl = ext;
}

NsRevocationUrlExtension
X509v3CertificateIssueExtensions::getNsRevocationUrl() const
{
    return nsRevocationUrl;
}

void
X509v3CertificateIssueExtensions::setNsCaRevocationUrl(const NsCaRevocationUrlExtension &ext)
{
    nsCaRevocationUrl = ext;
}

NsCaRevocationUrlExtension
X509v3CertificateIssueExtensions::getNsCaRevocationUrl() const
{
    return nsCaRevocationUrl;
}

void
X509v3CertificateIssueExtensions::setNsRenewalUrl(const NsRenewalUrlExtension &ext)
{
    nsRenewalUrl = ext;
}

NsRenewalUrlExtension
X509v3CertificateIssueExtensions::getNsRenewalUrl() const
{
    return nsRenewalUrl;
}

void
X509v3CertificateIssueExtensions::setNsCaPolicyUrl(const NsCaPolicyUrlExtension &ext)
{
    nsCaPolicyUrl = ext;
}

NsCaPolicyUrlExtension
X509v3CertificateIssueExtensions::getNsCaPolicyUrl()
{
    return nsCaPolicyUrl;
}

void
X509v3CertificateIssueExtensions::setNsSslServerName(const NsSslServerNameExtension &ext)
{
    nsSslServerName = ext;
}

NsSslServerNameExtension
X509v3CertificateIssueExtensions::getNsSslServerName() const
{
    return nsSslServerName;
}

void
X509v3CertificateIssueExtensions::setNsComment(const NsCommentExtension &ext)
{
    nsComment = ext;
}

NsCommentExtension
X509v3CertificateIssueExtensions::getNsComment() const
{
    return nsComment;
}

void
X509v3CertificateIssueExtensions::setNsCertType(const NsCertTypeExtension &ext)
{
    nsCertType = ext;
}

NsCertTypeExtension
X509v3CertificateIssueExtensions::getNsCertType() const
{
    return nsCertType;
}

void
X509v3CertificateIssueExtensions::setKeyUsage(const KeyUsageExtension &ext)
{
    keyUsage = ext;
}

KeyUsageExtension
X509v3CertificateIssueExtensions::getKeyUsage()
{
    return keyUsage;
}

void
X509v3CertificateIssueExtensions::setBasicConstraints(const BasicConstraintsExtension &ext)
{
    basicConstraints = ext;
}

BasicConstraintsExtension
X509v3CertificateIssueExtensions::getBasicConstraints() const
{
    return basicConstraints;
}

void
X509v3CertificateIssueExtensions::setExtendedKeyUsage(const ExtendedKeyUsageExtension &ext)
{
    extendedKeyUsage = ext;
}

ExtendedKeyUsageExtension
X509v3CertificateIssueExtensions::getExtendedKeyUsage() const
{
    return extendedKeyUsage;
}

void
X509v3CertificateIssueExtensions::setSubjectKeyIdentifier(const SubjectKeyIdentifierExtension &ext)
{
    subjectKeyIdentifier = ext;
}

SubjectKeyIdentifierExtension
X509v3CertificateIssueExtensions::getSubjectKeyIdentifier() const
{
    return subjectKeyIdentifier;
}

void
X509v3CertificateIssueExtensions::setAuthorityKeyIdentifier(const AuthorityKeyIdentifierGenerateExtension &ext)
{
    authorityKeyIdentifier = ext;
}

AuthorityKeyIdentifierGenerateExtension
X509v3CertificateIssueExtensions::getAuthorityKeyIdentifier() const
{
    return authorityKeyIdentifier;
}

void
X509v3CertificateIssueExtensions::setSubjectAlternativeName(const SubjectAlternativeNameExtension &ext)
{
    subjectAlternativeName = ext;
}

SubjectAlternativeNameExtension
X509v3CertificateIssueExtensions::getSubjectAlternativeName() const
{
    return subjectAlternativeName;
}
        
void
X509v3CertificateIssueExtensions::setIssuerAlternativeName(const IssuerAlternativeNameExtension &ext)
{
    issuerAlternativeName = ext;
}

IssuerAlternativeNameExtension
X509v3CertificateIssueExtensions::getIssuerAlternativeName() const
{
    return issuerAlternativeName;
}
                                                                     
void
X509v3CertificateIssueExtensions::setAuthorityInfoAccess(const AuthorityInfoAccessExtension &ext)
{
    authorityInfoAccess = ext;
}

AuthorityInfoAccessExtension
X509v3CertificateIssueExtensions::getAuthorityInfoAccess() const
{
    return authorityInfoAccess;
}

void
X509v3CertificateIssueExtensions::setCRLDistributionPoints(const CRLDistributionPointsExtension &ext)
{
    crlDistributionPoints = ext;
}

CRLDistributionPointsExtension
X509v3CertificateIssueExtensions::getCRLDistributionPoints() const
{
    return crlDistributionPoints;
}

void
X509v3CertificateIssueExtensions::setCertificatePolicies(const CertificatePoliciesExtension &ext)
{
    certificatePolicies = ext;
}

CertificatePoliciesExtension
X509v3CertificateIssueExtensions::getCertificatePolicies() const
{
    return certificatePolicies;
}

void
X509v3CertificateIssueExtensions::commit2Config(CA& ca, Type type)
{
}

