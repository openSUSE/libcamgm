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

X509v3CertificateExts::X509v3CertificateExts(const X509v3CertificateExts& extensions)
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

X509v3CertificateExts::~X509v3CertificateExts()
{
}

X509v3CertificateExts&
X509v3CertificateExts::operator=(const X509v3CertificateExts& extensions)
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

NsBaseUrlExt
X509v3CertificateExts::getNsBaseUrl() const
{
    return nsBaseUrl;
}

NsRevocationUrlExt
X509v3CertificateExts::getNsRevocationUrl() const
{
    return nsRevocationUrl;
}

NsCaRevocationUrlExt
X509v3CertificateExts::getNsCaRevocationUrl() const
{
    return nsCaRevocationUrl;
}

NsRenewalUrlExt
X509v3CertificateExts::getNsRenewalUrl() const
{
    return nsRenewalUrl;
}

NsCaPolicyUrlExt
X509v3CertificateExts::getNsCaPolicyUrl() const
{
    return nsCaPolicyUrl;
}

NsSslServerNameExt
X509v3CertificateExts::getNsSslServerName() const
{
    return nsSslServerName;
}

NsCommentExt
X509v3CertificateExts::getNsComment() const
{
    return nsComment;
}

NsCertTypeExt
X509v3CertificateExts::getNsCertType() const
{
    return nsCertType;
}

KeyUsageExt
X509v3CertificateExts::getKeyUsage() const
{
    return keyUsage;
}

BasicConstraintsExt
X509v3CertificateExts::getBasicConstraints() const
{
    return basicConstraints;
}

ExtendedKeyUsageExt
X509v3CertificateExts::getExtendedKeyUsage() const
{
    return extendedKeyUsage;
}

SubjectKeyIdentifierExt
X509v3CertificateExts::getSubjectKeyIdentifier() const
{
    return subjectKeyIdentifier;
}

AuthorityKeyIdentifierExt
X509v3CertificateExts::getAuthorityKeyIdentifier() const
{
    return authorityKeyIdentifier;
}

SubjectAlternativeNameExt
X509v3CertificateExts::getSubjectAlternativeName() const
{
    return subjectAlternativeName;
}

IssuerAlternativeNameExt
X509v3CertificateExts::getIssuerAlternativeName() const
{
    return issuerAlternativeName;
}

AuthorityInfoAccessExt
X509v3CertificateExts::getAuthorityInfoAccess() const
{
    return authorityInfoAccess;
}

CRLDistributionPointsExt
X509v3CertificateExts::getCRLDistributionPoints() const
{
    return crlDistributionPoints;
}

CertificatePoliciesExt
X509v3CertificateExts::getCertificatePolicies() const
{
    return certificatePolicies;
}

bool
X509v3CertificateExts::valid() const
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
X509v3CertificateExts::verify() const
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

    LOGIT_DEBUG_STRINGARRAY("X509v3CertificateExts::verify()", result);
    return result;
}

blocxx::StringArray
X509v3CertificateExts::dump() const
{
    StringArray result;
    result.append("X509v3CertificateExts::dump()");

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
X509v3CertificateExts::X509v3CertificateExts()
{
}

}
}
