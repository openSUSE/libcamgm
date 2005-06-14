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

  File:       X509v3CertificateExtensions.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/X509v3CertificateExtensions.hpp>

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

X509v3CertificateExtensions::X509v3CertificateExtensions(const X509v3CertificateExtensions& extensions)
{
}

X509v3CertificateExtensions::~X509v3CertificateExtensions()
{
}

X509v3CertificateExtensions&
X509v3CertificateExtensions::operator=(const X509v3CertificateExtensions& extensions)
{
    return *this;
}

NsBaseUrlExtension
X509v3CertificateExtensions::getNsBaseUrl() const
{
    return nsBaseUrl;
}

NsRevocationUrlExtension
X509v3CertificateExtensions::getNsRevocationUrl() const
{
    return nsRevocationUrl;
}

NsCaRevocationUrlExtension
X509v3CertificateExtensions::getNsCaRevocationUrl() const
{
    return nsCaRevocationUrl;
}

NsRenewalUrlExtension
X509v3CertificateExtensions::getNsRenewalUrl() const
{
    return nsRenewalUrl;
}

NsCaPolicyUrlExtension
X509v3CertificateExtensions::getNsCaPolicyUrl() const
{
    return nsCaPolicyUrl;
}

NsSslServerNameExtension
X509v3CertificateExtensions::getNsSslServerName() const
{
    return nsSslServerName;
}

NsCommentExtension
X509v3CertificateExtensions::getNsComment() const
{
    return nsComment;
}

NsCertTypeExtension
X509v3CertificateExtensions::getNsCertType() const
{
    return nsCertType;
}

KeyUsageExtension
X509v3CertificateExtensions::getKeyUsage() const
{
    return keyUsage;
}

BasicConstraintsExtension
X509v3CertificateExtensions::getBasicConstraints() const
{
    return basicConstraints;
}

ExtendedKeyUsageExtension
X509v3CertificateExtensions::getExtendedKeyUsage() const
{
    return extendedKeyUsage;
}

SubjectKeyIdentifierExtension
X509v3CertificateExtensions::getSubjectKeyIdentifier() const
{
    return subjectKeyIdentifier;
}

AuthorityKeyIdentifierExtension
X509v3CertificateExtensions::getAuthorityKeyIdentifier() const
{
    return authorityKeyIdentifier;
}

SubjectAlternativeNameExtension
X509v3CertificateExtensions::getSubjectAlternativeName() const
{
    return subjectAlternativeName;
}

IssuerAlternativeNameExtension
X509v3CertificateExtensions::getIssuerAlternativeName() const
{
    return issuerAlternativeName;
}

AuthorityInfoAccessExtension
X509v3CertificateExtensions::getAuthorityInfoAccess() const
{
    return authorityInfoAccess;
}

CRLDistributionPointsExtension
X509v3CertificateExtensions::getCRLDistributionPoints() const
{
    return crlDistributionPoints;
}

CertificatePoliciesExtension
X509v3CertificateExtensions::getCertificatePolicies() const
{
    return certificatePolicies;
}

        
//    protected:
X509v3CertificateExtensions::X509v3CertificateExtensions()
{
}

