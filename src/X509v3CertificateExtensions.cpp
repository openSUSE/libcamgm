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

#include  "X509v3CertificateExtensionsImpl.hpp"
#include  "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;
using namespace blocxx;

X509v3CertificateExts::X509v3CertificateExts(const X509v3CertificateExts& extensions)
	: m_impl(extensions.m_impl)
{}

X509v3CertificateExts::~X509v3CertificateExts()
{}

X509v3CertificateExts&
X509v3CertificateExts::operator=(const X509v3CertificateExts& extensions)
{
	if(this == &extensions) return *this;

	m_impl  = extensions.m_impl;

	return *this;
}

NsBaseUrlExt
X509v3CertificateExts::getNsBaseUrl() const
{
	return m_impl->nsBaseUrl;
}

NsRevocationUrlExt
X509v3CertificateExts::getNsRevocationUrl() const
{
	return m_impl->nsRevocationUrl;
}

NsCaRevocationUrlExt
X509v3CertificateExts::getNsCaRevocationUrl() const
{
	return m_impl->nsCaRevocationUrl;
}

NsRenewalUrlExt
X509v3CertificateExts::getNsRenewalUrl() const
{
	return m_impl->nsRenewalUrl;
}

NsCaPolicyUrlExt
X509v3CertificateExts::getNsCaPolicyUrl() const
{
	return m_impl->nsCaPolicyUrl;
}

NsSslServerNameExt
X509v3CertificateExts::getNsSslServerName() const
{
	return m_impl->nsSslServerName;
}

NsCommentExt
X509v3CertificateExts::getNsComment() const
{
	return m_impl->nsComment;
}

NsCertTypeExt
X509v3CertificateExts::getNsCertType() const
{
	return m_impl->nsCertType;
}

KeyUsageExt
X509v3CertificateExts::getKeyUsage() const
{
	return m_impl->keyUsage;
}

BasicConstraintsExt
X509v3CertificateExts::getBasicConstraints() const
{
	return m_impl->basicConstraints;
}

ExtendedKeyUsageExt
X509v3CertificateExts::getExtendedKeyUsage() const
{
	return m_impl->extendedKeyUsage;
}

SubjectKeyIdentifierExt
X509v3CertificateExts::getSubjectKeyIdentifier() const
{
	return m_impl->subjectKeyIdentifier;
}

AuthorityKeyIdentifierExt
X509v3CertificateExts::getAuthorityKeyIdentifier() const
{
	return m_impl->authorityKeyIdentifier;
}

SubjectAlternativeNameExt
X509v3CertificateExts::getSubjectAlternativeName() const
{
	return m_impl->subjectAlternativeName;
}

IssuerAlternativeNameExt
X509v3CertificateExts::getIssuerAlternativeName() const
{
	return m_impl->issuerAlternativeName;
}

AuthorityInfoAccessExt
X509v3CertificateExts::getAuthorityInfoAccess() const
{
	return m_impl->authorityInfoAccess;
}

CRLDistributionPointsExt
X509v3CertificateExts::getCRLDistributionPoints() const
{
	return m_impl->crlDistributionPoints;
}

CertificatePoliciesExt
X509v3CertificateExts::getCertificatePolicies() const
{
	return m_impl->certificatePolicies;
}

bool
X509v3CertificateExts::valid() const
{
	if(!m_impl->nsBaseUrl.valid()) return false;
	if(!m_impl->nsRevocationUrl.valid()) return false;
	if(!m_impl->nsCaRevocationUrl.valid()) return false;
	if(!m_impl->nsRenewalUrl.valid()) return false;
	if(!m_impl->nsCaPolicyUrl.valid()) return false;
	if(!m_impl->nsSslServerName.valid()) return false;
	if(!m_impl->nsComment.valid()) return false;
	if(!m_impl->keyUsage.valid()) return false;
	if(!m_impl->nsCertType.valid()) return false;
	if(!m_impl->basicConstraints.valid()) return false;
	if(!m_impl->extendedKeyUsage.valid()) return false;
	if(!m_impl->subjectKeyIdentifier.valid()) return false;
	if(!m_impl->authorityKeyIdentifier.valid()) return false;
	if(!m_impl->subjectAlternativeName.valid()) return false;
	if(!m_impl->issuerAlternativeName.valid()) return false;
	if(!m_impl->authorityInfoAccess.valid()) return false;
	if(!m_impl->crlDistributionPoints.valid()) return false;
	if(!m_impl->certificatePolicies.valid()) return false;
	return true;
}

std::vector<blocxx::String>
X509v3CertificateExts::verify() const
{
	std::vector<blocxx::String> result;

	appendArray(result, m_impl->nsBaseUrl.verify());
	appendArray(result, m_impl->nsRevocationUrl.verify());
	appendArray(result, m_impl->nsCaRevocationUrl.verify());
	appendArray(result, m_impl->nsRenewalUrl.verify());
	appendArray(result, m_impl->nsCaPolicyUrl.verify());
	appendArray(result, m_impl->nsSslServerName.verify());
	appendArray(result, m_impl->nsComment.verify());
	appendArray(result, m_impl->keyUsage.verify());
	appendArray(result, m_impl->nsCertType.verify());
	appendArray(result, m_impl->basicConstraints.verify());
	appendArray(result, m_impl->extendedKeyUsage.verify());
	appendArray(result, m_impl->subjectKeyIdentifier.verify());
	appendArray(result, m_impl->authorityKeyIdentifier.verify());
	appendArray(result, m_impl->subjectAlternativeName.verify());
	appendArray(result, m_impl->issuerAlternativeName.verify());
	appendArray(result, m_impl->authorityInfoAccess.verify());
	appendArray(result, m_impl->crlDistributionPoints.verify());
	appendArray(result, m_impl->certificatePolicies.verify());

	LOGIT_DEBUG_STRINGARRAY("X509v3CertificateExts::verify()", result);
	return result;
}

std::vector<blocxx::String>
X509v3CertificateExts::dump() const
{
	std::vector<blocxx::String> result;
	result.push_back("X509v3CertificateExts::dump()");

	appendArray(result, m_impl->nsBaseUrl.dump());
	appendArray(result, m_impl->nsRevocationUrl.dump());
	appendArray(result, m_impl->nsCaRevocationUrl.dump());
	appendArray(result, m_impl->nsRenewalUrl.dump());
	appendArray(result, m_impl->nsCaPolicyUrl.dump());
	appendArray(result, m_impl->nsSslServerName.dump());
	appendArray(result, m_impl->nsComment.dump());
	appendArray(result, m_impl->keyUsage.dump());
	appendArray(result, m_impl->nsCertType.dump());
	appendArray(result, m_impl->basicConstraints.dump());
	appendArray(result, m_impl->extendedKeyUsage.dump());
	appendArray(result, m_impl->subjectKeyIdentifier.dump());
	appendArray(result, m_impl->authorityKeyIdentifier.dump());
	appendArray(result, m_impl->subjectAlternativeName.dump());
	appendArray(result, m_impl->issuerAlternativeName.dump());
	appendArray(result, m_impl->authorityInfoAccess.dump());
	appendArray(result, m_impl->crlDistributionPoints.dump());
	appendArray(result, m_impl->certificatePolicies.dump());

	return result;
}

//    protected:
X509v3CertificateExts::X509v3CertificateExts()
	: m_impl(new X509v3CertificateExtsImpl())
{}

}
