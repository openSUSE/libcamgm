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
#include  <limal/Exception.hpp>

#include  "Utils.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;

X509v3CertificateExtensions::X509v3CertificateExtensions(const X509v3CertificateExtensions& extensions)
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

X509v3CertificateExtensions::~X509v3CertificateExtensions()
{
}

X509v3CertificateExtensions&
X509v3CertificateExtensions::operator=(const X509v3CertificateExtensions& extensions)
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

ExtendedKeyUsageExt
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

bool
X509v3CertificateExtensions::valid() const
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
X509v3CertificateExtensions::verify() const
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

    LOGIT_DEBUG_STRINGARRAY("X509v3CertificateExtensions::verify()", result);
    return result;
}

blocxx::StringArray
X509v3CertificateExtensions::dump() const
{
    StringArray result;
    result.append("X509v3CertificateExtensions::dump()");

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
        
//    protected:
X509v3CertificateExtensions::X509v3CertificateExtensions()
{
}

}
}
