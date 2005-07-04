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

  File:       X509v3CertificateExtensions_Priv.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  "X509v3CertificateExtensions_Priv.hpp"
#include  <limal/Exception.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

X509v3CertificateExtensions_Priv::X509v3CertificateExtensions_Priv()
    : X509v3CertificateExtensions()
{
}

X509v3CertificateExtensions_Priv::X509v3CertificateExtensions_Priv(X509* cert)
    : X509v3CertificateExtensions()
{
}

X509v3CertificateExtensions_Priv::~X509v3CertificateExtensions_Priv()
{
}

void
X509v3CertificateExtensions_Priv::setNsBaseUrl(const NsBaseUrlExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    nsBaseUrl = ext;
}

void
X509v3CertificateExtensions_Priv::setNsRevocationUrl(const NsRevocationUrlExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    nsRevocationUrl = ext;
}

void
X509v3CertificateExtensions_Priv::setNsCaRevocationUrl(const NsCaRevocationUrlExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    nsCaRevocationUrl = ext;
}

void
X509v3CertificateExtensions_Priv::setNsRenewalUrl(const NsRenewalUrlExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    nsRenewalUrl = ext;
}

void
X509v3CertificateExtensions_Priv::setNsCaPolicyUrl(const NsCaPolicyUrlExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    nsCaPolicyUrl = ext;
}

void
X509v3CertificateExtensions_Priv::setNsSslServerName(const NsSslServerNameExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    nsSslServerName = ext;
}

void
X509v3CertificateExtensions_Priv::setNsComment(const NsCommentExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    nsComment = ext;
}

void
X509v3CertificateExtensions_Priv::setNsCertType(const NsCertTypeExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    nsCertType = ext;
}

void
X509v3CertificateExtensions_Priv::setKeyUsage(const KeyUsageExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    keyUsage = ext;
}

void
X509v3CertificateExtensions_Priv::setBasicConstraints(const BasicConstraintsExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    basicConstraints = ext;
}

void
X509v3CertificateExtensions_Priv::setExtendedKeyUsage(const ExtendedKeyUsageExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    extendedKeyUsage = ext;
}

void
X509v3CertificateExtensions_Priv::setSubjectKeyIdentifier(const SubjectKeyIdentifierExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    subjectKeyIdentifier = ext;
}

void
X509v3CertificateExtensions_Priv::setAuthorityKeyIdentifier(const AuthorityKeyIdentifierExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    authorityKeyIdentifier = ext;
}

void
X509v3CertificateExtensions_Priv::setSubjectAlternativeName(const SubjectAlternativeNameExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    subjectAlternativeName = ext;
}

void
X509v3CertificateExtensions_Priv::setIssuerAlternativeName(const IssuerAlternativeNameExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    issuerAlternativeName = ext;
}

void
X509v3CertificateExtensions_Priv::setAuthorityInfoAccess(const AuthorityInfoAccessExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    authorityInfoAccess = ext;
}

void
X509v3CertificateExtensions_Priv::setCRLDistributionPoints(const CRLDistributionPointsExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    crlDistributionPoints = ext;
}

void
X509v3CertificateExtensions_Priv::setCertificatePolicies(const CertificatePoliciesExtension &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    certificatePolicies = ext;
}


//    private:
X509v3CertificateExtensions_Priv::X509v3CertificateExtensions_Priv(const X509v3CertificateExtensions_Priv& extensions)
    : X509v3CertificateExtensions(extensions)
{
}

X509v3CertificateExtensions_Priv&
X509v3CertificateExtensions_Priv::operator=(const X509v3CertificateExtensions_Priv& extensions)
{
    if(this == &extensions) return *this;
    
    X509v3CertificateExtensions::operator=(extensions);

    return *this;
}
