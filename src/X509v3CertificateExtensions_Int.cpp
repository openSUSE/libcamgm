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

  File:       X509v3CertificateExtensions_Int.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  "X509v3CertificateExtensions_Int.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

X509v3CertificateExtensions_Int::X509v3CertificateExtensions_Int()
    : X509v3CertificateExtensions()
{
}

X509v3CertificateExtensions_Int::X509v3CertificateExtensions_Int(X509* cert)
    : X509v3CertificateExtensions()
{
}

X509v3CertificateExtensions_Int::~X509v3CertificateExtensions_Int()
{
}

void
X509v3CertificateExtensions_Int::setNsBaseUrl(const NsBaseUrlExtension &ext)
{
    nsBaseUrl = ext;
}

void
X509v3CertificateExtensions_Int::setNsRevocationUrl(const NsRevocationUrlExtension &ext)
{
    nsRevocationUrl = ext;
}

void
X509v3CertificateExtensions_Int::setNsCaRevocationUrl(const NsCaRevocationUrlExtension &ext)
{
    nsCaRevocationUrl = ext;
}

void
X509v3CertificateExtensions_Int::setNsRenewalUrl(const NsRenewalUrlExtension &ext)
{
    nsRenewalUrl = ext;
}

void
X509v3CertificateExtensions_Int::setNsCaPolicyUrl(const NsCaPolicyUrlExtension &ext)
{
    nsCaPolicyUrl = ext;
}

void
X509v3CertificateExtensions_Int::setNsSslServerName(const NsSslServerNameExtension &ext)
{
    nsSslServerName = ext;
}

void
X509v3CertificateExtensions_Int::setNsComment(const NsCommentExtension &ext)
{
    nsComment = ext;
}

void
X509v3CertificateExtensions_Int::setNsCertType(const NsCertTypeExtension &ext)
{
    nsCertType = ext;
}

void
X509v3CertificateExtensions_Int::setKeyUsage(const KeyUsageExtension &ext)
{
    keyUsage = ext;
}

void
X509v3CertificateExtensions_Int::setBasicConstraints(const BasicConstraintsExtension &ext)
{
    basicConstraints = ext;
}

void
X509v3CertificateExtensions_Int::setExtendedKeyUsage(const ExtendedKeyUsageExtension &ext)
{
    extendedKeyUsage = ext;
}

void
X509v3CertificateExtensions_Int::setSubjectKeyIdentifier(const SubjectKeyIdentifierExtension &ext)
{
    subjectKeyIdentifier = ext;
}

void
X509v3CertificateExtensions_Int::setAuthorityKeyIdentifier(const AuthorityKeyIdentifierExtension &ext)
{
    authorityKeyIdentifier = ext;
}

void
X509v3CertificateExtensions_Int::setSubjectAlternativeName(const SubjectAlternativeNameExtension &ext)
{
    subjectAlternativeName = ext;
}

void
X509v3CertificateExtensions_Int::setIssuerAlternativeName(const IssuerAlternativeNameExtension &ext)
{
    issuerAlternativeName = ext;
}

void
X509v3CertificateExtensions_Int::setAuthorityInfoAccess(const AuthorityInfoAccessExtension &ext)
{
    authorityInfoAccess = ext;
}

void
X509v3CertificateExtensions_Int::setCRLDistributionPoints(const CRLDistributionPointsExtension &ext)
{
    crlDistributionPoints = ext;
}

void
X509v3CertificateExtensions_Int::setCertificatePolicies(const CertificatePoliciesExtension &ext)
{
    certificatePolicies = ext;
}


//    private:
X509v3CertificateExtensions_Int::X509v3CertificateExtensions_Int(const X509v3CertificateExtensions_Int& extensions)
    : X509v3CertificateExtensions(extensions)
{
}

X509v3CertificateExtensions_Int&
X509v3CertificateExtensions_Int::operator=(const X509v3CertificateExtensions_Int& extensions)
{
    return *this;
}
