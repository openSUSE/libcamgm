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

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;

X509v3CertificateIssueExts::X509v3CertificateIssueExts()
{
}

X509v3CertificateIssueExts::X509v3CertificateIssueExts(CAConfig* caConfig,
                                                       Type type)
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

X509v3CertificateIssueExts::X509v3CertificateIssueExts(const X509v3CertificateIssueExts& extensions)
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

X509v3CertificateIssueExts::~X509v3CertificateIssueExts()
{}

X509v3CertificateIssueExts&
X509v3CertificateIssueExts::operator=(const X509v3CertificateIssueExts& extensions)
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
X509v3CertificateIssueExts::setNsBaseUrl(const NsBaseUrlExt &ext)
{
    if(!ext.valid())
    {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExts::setNsBaseUrl invalid value");
    }
    nsBaseUrl = ext;
}

NsBaseUrlExt
X509v3CertificateIssueExts::getNsBaseUrl() const
{
    return nsBaseUrl;
}

void
X509v3CertificateIssueExts::setNsRevocationUrl(const NsRevocationUrlExt &ext)
{
    if(!ext.valid())
    {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExts::setNsRevocationUrl invalid value");
    }
    nsRevocationUrl = ext;
}

NsRevocationUrlExt
X509v3CertificateIssueExts::getNsRevocationUrl() const
{
    return nsRevocationUrl;
}

void
X509v3CertificateIssueExts::setNsCaRevocationUrl(const NsCaRevocationUrlExt &ext)
{
    if(!ext.valid())
    {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExts::setNsCaRevocationUrl invalid value");
    }
    nsCaRevocationUrl = ext;
}

NsCaRevocationUrlExt
X509v3CertificateIssueExts::getNsCaRevocationUrl() const
{
    return nsCaRevocationUrl;
}

void
X509v3CertificateIssueExts::setNsRenewalUrl(const NsRenewalUrlExt &ext)
{
    if(!ext.valid())
    {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExts::setNsRenewalUrl invalid value");
    }
    nsRenewalUrl = ext;
}

NsRenewalUrlExt
X509v3CertificateIssueExts::getNsRenewalUrl() const
{
    return nsRenewalUrl;
}

void
X509v3CertificateIssueExts::setNsCaPolicyUrl(const NsCaPolicyUrlExt &ext)
{
    if(!ext.valid())
    {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExts::setNsCaPolicyUrl invalid value");
    }
    nsCaPolicyUrl = ext;
}

NsCaPolicyUrlExt
X509v3CertificateIssueExts::getNsCaPolicyUrl()
{
    return nsCaPolicyUrl;
}

void
X509v3CertificateIssueExts::setNsSslServerName(const NsSslServerNameExt &ext)
{
    if(!ext.valid())
    {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExts::setNsSslServerName invalid value");
    }
    nsSslServerName = ext;
}

NsSslServerNameExt
X509v3CertificateIssueExts::getNsSslServerName() const
{
    return nsSslServerName;
}

void
X509v3CertificateIssueExts::setNsComment(const NsCommentExt &ext)
{
    if(!ext.valid())
    {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExts::setNsComment invalid value");
    }
    nsComment = ext;
}

NsCommentExt
X509v3CertificateIssueExts::getNsComment() const
{
    return nsComment;
}

void
X509v3CertificateIssueExts::setNsCertType(const NsCertTypeExt &ext)
{
    if(!ext.valid())
    {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExts::setNsCertType invalid value");
    }
    nsCertType = ext;
}

NsCertTypeExt
X509v3CertificateIssueExts::getNsCertType() const
{
    return nsCertType;
}

void
X509v3CertificateIssueExts::setKeyUsage(const KeyUsageExt &ext)
{
    if(!ext.valid())
    {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExts::setKeyUsage invalid value");
    }
    keyUsage = ext;
}

KeyUsageExt
X509v3CertificateIssueExts::getKeyUsage()
{
    return keyUsage;
}

void
X509v3CertificateIssueExts::setBasicConstraints(const BasicConstraintsExt &ext)
{
    if(!ext.valid())
    {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExts::setBasicConstraints invalid value");
    }
    basicConstraints = ext;
}

BasicConstraintsExt
X509v3CertificateIssueExts::getBasicConstraints() const
{
    return basicConstraints;
}

void
X509v3CertificateIssueExts::setExtendedKeyUsage(const ExtendedKeyUsageExt &ext)
{
    if(!ext.valid())
    {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExts::setExtendedKeyUsage invalid value");
    }
    extendedKeyUsage = ext;
}

ExtendedKeyUsageExt
X509v3CertificateIssueExts::getExtendedKeyUsage() const
{
    return extendedKeyUsage;
}

void
X509v3CertificateIssueExts::setSubjectKeyIdentifier(const SubjectKeyIdentifierExt &ext)
{
    if(!ext.valid())
    {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExts::setSubjectKeyIdentifier invalid value");
    }
    subjectKeyIdentifier = ext;
}

SubjectKeyIdentifierExt
X509v3CertificateIssueExts::getSubjectKeyIdentifier() const
{
    return subjectKeyIdentifier;
}

void
X509v3CertificateIssueExts::setAuthorityKeyIdentifier(const AuthorityKeyIdentifierGenerateExt &ext)
{
    if(!ext.valid())
    {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExts::setAuthorityKeyIdentifier invalid value");
    }
    authorityKeyIdentifier = ext;
}

AuthorityKeyIdentifierGenerateExt
X509v3CertificateIssueExts::getAuthorityKeyIdentifier() const
{
    return authorityKeyIdentifier;
}

void
X509v3CertificateIssueExts::setSubjectAlternativeName(const SubjectAlternativeNameExt &ext)
{
    if(!ext.valid())
    {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExts::setSubjectAlternativeName invalid value");
    }
    subjectAlternativeName = ext;
}

SubjectAlternativeNameExt
X509v3CertificateIssueExts::getSubjectAlternativeName() const
{
    return subjectAlternativeName;
}
        
void
X509v3CertificateIssueExts::setIssuerAlternativeName(const IssuerAlternativeNameExt &ext)
{
    if(!ext.valid())
    {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExts::setIssuerAlternativeName invalid value");
    }
    issuerAlternativeName = ext;
}

IssuerAlternativeNameExt
X509v3CertificateIssueExts::getIssuerAlternativeName() const
{
    return issuerAlternativeName;
}
                                                                     
void
X509v3CertificateIssueExts::setAuthorityInfoAccess(const AuthorityInfoAccessExt &ext)
{
    if(!ext.valid())
    {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExts::setAuthorityInfoAccess invalid value");
    }
    authorityInfoAccess = ext;
}

AuthorityInfoAccessExt
X509v3CertificateIssueExts::getAuthorityInfoAccess() const
{
    return authorityInfoAccess;
}

void
X509v3CertificateIssueExts::setCRLDistributionPoints(const CRLDistributionPointsExt &ext)
{
    if(!ext.valid())
    {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExts::setCRLDistributionPoints invalid value");
    }
    crlDistributionPoints = ext;
}

CRLDistributionPointsExt
X509v3CertificateIssueExts::getCRLDistributionPoints() const
{
    return crlDistributionPoints;
}

void
X509v3CertificateIssueExts::setCertificatePolicies(const CertificatePoliciesExt &ext)
{
    if(!ext.valid())
    {
        BLOCXX_THROW(limal::ValueException, 
                     "X509v3CertificateIssueExts::setCertificatePolicies invalid value");
    }
    certificatePolicies = ext;
}

CertificatePoliciesExt
X509v3CertificateIssueExts::getCertificatePolicies() const
{
    return certificatePolicies;
}

void
X509v3CertificateIssueExts::commit2Config(CA& ca, Type type) const
{
    if(!valid())
    {
        LOGIT_ERROR("invalid X509v3RequestExts object");
        BLOCXX_THROW(limal::ValueException, "invalid X509v3RequestExts object");
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
X509v3CertificateIssueExts::valid() const
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
X509v3CertificateIssueExts::verify() const
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

    LOGIT_DEBUG_STRINGARRAY("X509v3CertificateIssueExts::verify()", result);
    return result;
}

blocxx::StringArray
X509v3CertificateIssueExts::dump() const
{
    StringArray result;
    result.append("X509v3CertificateIssueExts::dump()");

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

}
}
