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
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/Exception.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

X509v3CertificateIssueExtensions::X509v3CertificateIssueExtensions()
{
}

X509v3CertificateIssueExtensions::X509v3CertificateIssueExtensions(CAConfig* caConfig, Type type)
    : nsBaseUrl(caConfig, type),
      nsRevocationUrl(caConfig, type),
      nsCaRevocationUrl(caConfig, type),
      nsRenewalUrl(caConfig, type),
      nsCaPolicyUrl(caConfig, type),
      nsSslServerName(caConfig, type),
      nsComment(caConfig, type),
      keyUsage(caConfig, type),
      nsCertType(caConfig, type),
      basicConstraints(caConfig, type),
      extendedKeyUsage(caConfig, type),
      subjectKeyIdentifier(caConfig, type),
      authorityKeyIdentifier(caConfig, type),
      subjectAlternativeName(caConfig, type),
      issuerAlternativeName(caConfig, type),
      authorityInfoAccess(caConfig, type),
      crlDistributionPoints(caConfig, type),
      certificatePolicies(caConfig, type)
{
}

X509v3CertificateIssueExtensions::X509v3CertificateIssueExtensions(const X509v3CertificateIssueExtensions& extensions)
    : nsBaseUrl(extensions.nsBaseUrl),
      nsRevocationUrl(extensions.nsRevocationUrl),
      nsCaRevocationUrl(extensions.nsCaRevocationUrl),
      nsRenewalUrl(extensions.nsRenewalUrl),
      nsCaPolicyUrl(extensions.nsCaPolicyUrl),
      nsSslServerName(extensions.nsSslServerName),
      nsComment(extensions.nsComment),
      keyUsage(extensions.keyUsage),
      nsCertType(extensions.nsCertType),
      basicConstraints(extensions.basicConstraints),
      extendedKeyUsage(extensions.extendedKeyUsage),
      subjectKeyIdentifier(extensions.subjectKeyIdentifier),
      authorityKeyIdentifier(extensions.authorityKeyIdentifier),
      subjectAlternativeName(extensions.subjectAlternativeName),
      issuerAlternativeName(extensions.issuerAlternativeName),
      authorityInfoAccess(extensions.authorityInfoAccess),
      crlDistributionPoints(extensions.crlDistributionPoints),
      certificatePolicies(extensions.certificatePolicies)
{
}

X509v3CertificateIssueExtensions::~X509v3CertificateIssueExtensions()
{}

X509v3CertificateIssueExtensions&
X509v3CertificateIssueExtensions::operator=(const X509v3CertificateIssueExtensions& extensions)
{
    if(this == &extensions) return *this;

    nsBaseUrl              = extensions.nsBaseUrl;
    nsRevocationUrl        = extensions.nsRevocationUrl;
    nsCaRevocationUrl      = extensions.nsCaRevocationUrl;
    nsRenewalUrl           = extensions.nsRenewalUrl;
    nsCaPolicyUrl          = extensions.nsCaPolicyUrl;
    nsSslServerName        = extensions.nsSslServerName;
    nsComment              = extensions.nsComment;
    keyUsage               = extensions.keyUsage;
    nsCertType             = extensions.nsCertType;
    basicConstraints       = extensions.basicConstraints;
    extendedKeyUsage       = extensions.extendedKeyUsage;
    subjectKeyIdentifier   = extensions.subjectKeyIdentifier;
    authorityKeyIdentifier = extensions.authorityKeyIdentifier;
    subjectAlternativeName = extensions.subjectAlternativeName;
    issuerAlternativeName  = extensions.issuerAlternativeName;
    authorityInfoAccess    = extensions.authorityInfoAccess;
    crlDistributionPoints  = extensions.crlDistributionPoints;
    certificatePolicies    = extensions.certificatePolicies;

    return *this;
}

void
X509v3CertificateIssueExtensions::setNsBaseUrl(const NsBaseUrlExtension &ext)
{
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExtensions::setNsBaseUrl invalid value");
    }
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
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExtensions::setNsRevocationUrl invalid value");
    }
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
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExtensions::setNsCaRevocationUrl invalid value");
    }
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
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExtensions::setNsRenewalUrl invalid value");
    }
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
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExtensions::setNsCaPolicyUrl invalid value");
    }
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
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExtensions::setNsSslServerName invalid value");
    }
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
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExtensions::setNsComment invalid value");
    }
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
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExtensions::setNsCertType invalid value");
    }
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
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExtensions::setKeyUsage invalid value");
    }
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
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExtensions::setBasicConstraints invalid value");
    }
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
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExtensions::setExtendedKeyUsage invalid value");
    }
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
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExtensions::setSubjectKeyIdentifier invalid value");
    }
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
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExtensions::setAuthorityKeyIdentifier invalid value");
    }
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
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExtensions::setSubjectAlternativeName invalid value");
    }
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
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExtensions::setIssuerAlternativeName invalid value");
    }
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
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExtensions::setAuthorityInfoAccess invalid value");
    }
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
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExtensions::setCRLDistributionPoints invalid value");
    }
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
    if(!ext.valid()) {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExtensions::setCertificatePolicies invalid value");
    }
    certificatePolicies = ext;
}

CertificatePoliciesExtension
X509v3CertificateIssueExtensions::getCertificatePolicies() const
{
    return certificatePolicies;
}

void
X509v3CertificateIssueExtensions::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid X509v3RequestExtensions object");
        BLOCXX_THROW(limal::ValueException, "invalid X509v3RequestExtensions object");
    }

    nsBaseUrl.commit2Config(ca, type);
    nsRevocationUrl.commit2Config(ca, type);
    nsCaRevocationUrl.commit2Config(ca, type);
    nsRenewalUrl.commit2Config(ca, type);
    nsCaPolicyUrl.commit2Config(ca, type);
    nsSslServerName.commit2Config(ca, type);
    nsComment.commit2Config(ca, type);
    keyUsage.commit2Config(ca, type);
    nsCertType.commit2Config(ca, type);
    basicConstraints.commit2Config(ca, type);
    extendedKeyUsage.commit2Config(ca, type);
    subjectKeyIdentifier.commit2Config(ca, type);
    authorityKeyIdentifier.commit2Config(ca, type);
    subjectAlternativeName.commit2Config(ca, type);
    issuerAlternativeName.commit2Config(ca, type);
    authorityInfoAccess.commit2Config(ca, type);
    crlDistributionPoints.commit2Config(ca, type);
    certificatePolicies.commit2Config(ca, type);
}

bool
X509v3CertificateIssueExtensions::valid() const
{
    if(!nsBaseUrl.valid()) return false;
    if(!nsRevocationUrl.valid()) return false;
    if(!nsCaRevocationUrl.valid()) return false;
    if(!nsRenewalUrl.valid()) return false;
    if(!nsCaPolicyUrl.valid()) return false;
    if(!nsSslServerName.valid()) return false;
    if(!nsComment.valid()) return false;
    if(!keyUsage.valid()) return false;
    if(!nsCertType.valid()) return false;
    if(!basicConstraints.valid()) return false;
    if(!extendedKeyUsage.valid()) return false;
    if(!subjectKeyIdentifier.valid()) return false;
    if(!authorityKeyIdentifier.valid()) return false;
    if(!subjectAlternativeName.valid()) return false;
    if(!issuerAlternativeName.valid()) return false;
    if(!authorityInfoAccess.valid()) return false;
    if(!crlDistributionPoints.valid()) return false;
    if(!certificatePolicies.valid()) return false;
    return true;
}

blocxx::StringArray
X509v3CertificateIssueExtensions::verify() const
{
    StringArray result;

    result.appendArray(nsBaseUrl.verify());
    result.appendArray(nsRevocationUrl.verify());
    result.appendArray(nsCaRevocationUrl.verify());
    result.appendArray(nsRenewalUrl.verify());
    result.appendArray(nsCaPolicyUrl.verify());
    result.appendArray(nsSslServerName.verify());
    result.appendArray(nsComment.verify());
    result.appendArray(keyUsage.verify());  
    result.appendArray(nsCertType.verify());   
    result.appendArray(basicConstraints.verify()); 
    result.appendArray(extendedKeyUsage.verify());
    result.appendArray(subjectKeyIdentifier.verify());
    result.appendArray(authorityKeyIdentifier.verify());
    result.appendArray(subjectAlternativeName.verify());
    result.appendArray(issuerAlternativeName.verify());
    result.appendArray(authorityInfoAccess.verify());
    result.appendArray(crlDistributionPoints.verify());
    result.appendArray(certificatePolicies.verify());

    LOGIT_DEBUG_STRINGARRAY("X509v3CertificateIssueExtensions::verify()", result);
    return result;
}

blocxx::StringArray
X509v3CertificateIssueExtensions::dump() const
{
    StringArray result;
    result.append("X509v3CertificateIssueExtensions::dump()");

    result.appendArray(nsBaseUrl.dump());
    result.appendArray(nsRevocationUrl.dump());
    result.appendArray(nsCaRevocationUrl.dump());
    result.appendArray(nsRenewalUrl.dump());
    result.appendArray(nsCaPolicyUrl.dump());
    result.appendArray(nsSslServerName.dump());
    result.appendArray(nsComment.dump());
    result.appendArray(keyUsage.dump());  
    result.appendArray(nsCertType.dump());   
    result.appendArray(basicConstraints.dump()); 
    result.appendArray(extendedKeyUsage.dump());
    result.appendArray(subjectKeyIdentifier.dump());
    result.appendArray(authorityKeyIdentifier.dump());
    result.appendArray(subjectAlternativeName.dump());
    result.appendArray(issuerAlternativeName.dump());
    result.appendArray(authorityInfoAccess.dump());
    result.appendArray(crlDistributionPoints.dump());
    result.appendArray(certificatePolicies.dump());

    return result;
}
