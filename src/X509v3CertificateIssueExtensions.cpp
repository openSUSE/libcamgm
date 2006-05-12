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
#include  <blocxx/COWIntrusiveCountableBase.hpp>

#include  "Utils.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;

class X509v3CertificateIssueExtsImpl : public blocxx::COWIntrusiveCountableBase
{
	public:
	X509v3CertificateIssueExtsImpl()
		: nsBaseUrl(NsBaseUrlExt()),
		  nsRevocationUrl(NsRevocationUrlExt()),
		  nsCaRevocationUrl(NsCaRevocationUrlExt()),
		  nsRenewalUrl(NsRenewalUrlExt()),
		  nsCaPolicyUrl(NsCaPolicyUrlExt()),
		  nsSslServerName(NsSslServerNameExt()),
		  nsComment(NsCommentExt()),
		  keyUsage(KeyUsageExt()),
		  nsCertType(NsCertTypeExt()),
		  basicConstraints(BasicConstraintsExt()),
		  extendedKeyUsage(ExtendedKeyUsageExt()),
		  subjectKeyIdentifier(SubjectKeyIdentifierExt()),
		  authorityKeyIdentifier(AuthorityKeyIdentifierGenerateExt()),
		  subjectAlternativeName(SubjectAlternativeNameExt()),
		  issuerAlternativeName(IssuerAlternativeNameExt()),
		  authorityInfoAccess(AuthorityInfoAccessExt()),
		  crlDistributionPoints(CRLDistributionPointsExt()),
		  certificatePolicies(CertificatePoliciesExt())
	{}

	X509v3CertificateIssueExtsImpl(CAConfig* caConfig,
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
	{}

	X509v3CertificateIssueExtsImpl(const X509v3CertificateIssueExtsImpl& impl)
		: COWIntrusiveCountableBase(impl),
		  nsBaseUrl(impl.nsBaseUrl),
		  nsRevocationUrl(impl.nsRevocationUrl),
		  nsCaRevocationUrl(impl.nsCaRevocationUrl),
		  nsRenewalUrl(impl.nsRenewalUrl),
		  nsCaPolicyUrl(impl.nsCaPolicyUrl),
		  nsSslServerName(impl.nsSslServerName),
		  nsComment(impl.nsComment),
		  keyUsage(impl.keyUsage),
		  nsCertType(impl.nsCertType),
		  basicConstraints(impl.basicConstraints),
		  extendedKeyUsage(impl.extendedKeyUsage),
		  subjectKeyIdentifier(impl.subjectKeyIdentifier),
		  authorityKeyIdentifier(impl.authorityKeyIdentifier),
		  subjectAlternativeName(impl.subjectAlternativeName),
		  issuerAlternativeName(impl.issuerAlternativeName),
		  authorityInfoAccess(impl.authorityInfoAccess),
		  crlDistributionPoints(impl.crlDistributionPoints),
		  certificatePolicies(impl.certificatePolicies)
	{}

	~X509v3CertificateIssueExtsImpl() {}

	X509v3CertificateIssueExtsImpl* clone() const
	{
		return new X509v3CertificateIssueExtsImpl(*this);
	}

	/* String extensions */

	NsBaseUrlExt                      nsBaseUrl;
	NsRevocationUrlExt                nsRevocationUrl;
	NsCaRevocationUrlExt              nsCaRevocationUrl;
	NsRenewalUrlExt                   nsRenewalUrl;
	NsCaPolicyUrlExt                  nsCaPolicyUrl;
	NsSslServerNameExt                nsSslServerName;
	NsCommentExt                      nsComment;
	
	/* Bit Strings */
	KeyUsageExt                       keyUsage;
	NsCertTypeExt                     nsCertType;
	
	BasicConstraintsExt               basicConstraints;
	ExtendedKeyUsageExt               extendedKeyUsage;
	SubjectKeyIdentifierExt           subjectKeyIdentifier;
	AuthorityKeyIdentifierGenerateExt authorityKeyIdentifier;
	SubjectAlternativeNameExt         subjectAlternativeName;
	IssuerAlternativeNameExt          issuerAlternativeName;
	
	AuthorityInfoAccessExt            authorityInfoAccess;
	CRLDistributionPointsExt          crlDistributionPoints;
	CertificatePoliciesExt            certificatePolicies;
	
};

	
X509v3CertificateIssueExts::X509v3CertificateIssueExts()
	: m_impl(new X509v3CertificateIssueExtsImpl())
{}

X509v3CertificateIssueExts::X509v3CertificateIssueExts(CAConfig* caConfig,
                                                       Type type)
	: m_impl(new X509v3CertificateIssueExtsImpl(caConfig, type))
{}

X509v3CertificateIssueExts::X509v3CertificateIssueExts(const X509v3CertificateIssueExts& extensions)
	: m_impl(extensions.m_impl)
{}

X509v3CertificateIssueExts::~X509v3CertificateIssueExts()
{}

X509v3CertificateIssueExts&
X509v3CertificateIssueExts::operator=(const X509v3CertificateIssueExts& extensions)
{
	if(this == &extensions) return *this;

	m_impl = extensions.m_impl;

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
	m_impl->nsBaseUrl = ext;
}

NsBaseUrlExt
X509v3CertificateIssueExts::getNsBaseUrl() const
{
	return m_impl->nsBaseUrl;
}

NsBaseUrlExt&
X509v3CertificateIssueExts::nsBaseUrl()
{
	return m_impl->nsBaseUrl;
}

void
X509v3CertificateIssueExts::setNsRevocationUrl(const NsRevocationUrlExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(limal::ValueException, 
		             "X509v3CertificateIssueExts::setNsRevocationUrl invalid value");
	}
	m_impl->nsRevocationUrl = ext;
}

NsRevocationUrlExt
X509v3CertificateIssueExts::getNsRevocationUrl() const
{
	return m_impl->nsRevocationUrl;
}

NsRevocationUrlExt&
X509v3CertificateIssueExts::nsRevocationUrl()
{
	return m_impl->nsRevocationUrl;
}

void
X509v3CertificateIssueExts::setNsCaRevocationUrl(const NsCaRevocationUrlExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(limal::ValueException, 
		             "X509v3CertificateIssueExts::setNsCaRevocationUrl invalid value");
	}
	m_impl->nsCaRevocationUrl = ext;
}

NsCaRevocationUrlExt
X509v3CertificateIssueExts::getNsCaRevocationUrl() const
{
	return m_impl->nsCaRevocationUrl;
}

NsCaRevocationUrlExt&
X509v3CertificateIssueExts::nsCaRevocationUrl()
{
	return m_impl->nsCaRevocationUrl;
}

void
X509v3CertificateIssueExts::setNsRenewalUrl(const NsRenewalUrlExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(limal::ValueException, 
		             "X509v3CertificateIssueExts::setNsRenewalUrl invalid value");
	}
	m_impl->nsRenewalUrl = ext;
}

NsRenewalUrlExt
X509v3CertificateIssueExts::getNsRenewalUrl() const
{
	return m_impl->nsRenewalUrl;
}

NsRenewalUrlExt&
X509v3CertificateIssueExts::nsRenewalUrl()
{
	return m_impl->nsRenewalUrl;
}

void
X509v3CertificateIssueExts::setNsCaPolicyUrl(const NsCaPolicyUrlExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(limal::ValueException, 
		             "X509v3CertificateIssueExts::setNsCaPolicyUrl invalid value");
	}
	m_impl->nsCaPolicyUrl = ext;
}

NsCaPolicyUrlExt
X509v3CertificateIssueExts::getNsCaPolicyUrl() const
{
	return m_impl->nsCaPolicyUrl;
}

NsCaPolicyUrlExt&
X509v3CertificateIssueExts::nsCaPolicyUrl()
{
	return m_impl->nsCaPolicyUrl;
}

void
X509v3CertificateIssueExts::setNsSslServerName(const NsSslServerNameExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(limal::ValueException, 
		             "X509v3CertificateIssueExts::setNsSslServerName invalid value");
	}
	m_impl->nsSslServerName = ext;
}

NsSslServerNameExt
X509v3CertificateIssueExts::getNsSslServerName() const
{
	return m_impl->nsSslServerName;
}

NsSslServerNameExt&
X509v3CertificateIssueExts::nsSslServerName()
{
	return m_impl->nsSslServerName;
}

void
X509v3CertificateIssueExts::setNsComment(const NsCommentExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(limal::ValueException, 
		             "X509v3CertificateIssueExts::setNsComment invalid value");
	}
	m_impl->nsComment = ext;
}

NsCommentExt
X509v3CertificateIssueExts::getNsComment() const
{
	return m_impl->nsComment;
}

NsCommentExt&
X509v3CertificateIssueExts::nsComment()
{
	return m_impl->nsComment;
}

void
X509v3CertificateIssueExts::setNsCertType(const NsCertTypeExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(limal::ValueException, 
		             "X509v3CertificateIssueExts::setNsCertType invalid value");
	}
	m_impl->nsCertType = ext;
}

NsCertTypeExt
X509v3CertificateIssueExts::getNsCertType() const
{
	return m_impl->nsCertType;
}

NsCertTypeExt&
X509v3CertificateIssueExts::nsCertType()
{
	return m_impl->nsCertType;
}

void
X509v3CertificateIssueExts::setKeyUsage(const KeyUsageExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(limal::ValueException, 
		             "X509v3CertificateIssueExts::setKeyUsage invalid value");
	}
	m_impl->keyUsage = ext;
}

KeyUsageExt
X509v3CertificateIssueExts::getKeyUsage() const
{
	return m_impl->keyUsage;
}

KeyUsageExt&
X509v3CertificateIssueExts::keyUsage()
{
	return m_impl->keyUsage;
}

void
X509v3CertificateIssueExts::setBasicConstraints(const BasicConstraintsExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(limal::ValueException, 
		             "X509v3CertificateIssueExts::setBasicConstraints invalid value");
	}
	m_impl->basicConstraints = ext;
}

BasicConstraintsExt
X509v3CertificateIssueExts::getBasicConstraints() const
{
	return m_impl->basicConstraints;
}

BasicConstraintsExt&
X509v3CertificateIssueExts::basicConstraints()
{
	return m_impl->basicConstraints;
}

void
X509v3CertificateIssueExts::setExtendedKeyUsage(const ExtendedKeyUsageExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(limal::ValueException, 
		             "X509v3CertificateIssueExts::setExtendedKeyUsage invalid value");
	}
	m_impl->extendedKeyUsage = ext;
}

ExtendedKeyUsageExt
X509v3CertificateIssueExts::getExtendedKeyUsage() const
{
	return m_impl->extendedKeyUsage;
}

ExtendedKeyUsageExt&
X509v3CertificateIssueExts::extendedKeyUsage()
{
	return m_impl->extendedKeyUsage;
}

void
X509v3CertificateIssueExts::setSubjectKeyIdentifier(const SubjectKeyIdentifierExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(limal::ValueException, 
		             "X509v3CertificateIssueExts::setSubjectKeyIdentifier invalid value");
	}
	m_impl->subjectKeyIdentifier = ext;
}

SubjectKeyIdentifierExt
X509v3CertificateIssueExts::getSubjectKeyIdentifier() const
{
	return m_impl->subjectKeyIdentifier;
}

SubjectKeyIdentifierExt&
X509v3CertificateIssueExts::subjectKeyIdentifier()
{
	return m_impl->subjectKeyIdentifier;
}

void
X509v3CertificateIssueExts::setAuthorityKeyIdentifier(const AuthorityKeyIdentifierGenerateExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(limal::ValueException, 
		             "X509v3CertificateIssueExts::setAuthorityKeyIdentifier invalid value");
	}
	m_impl->authorityKeyIdentifier = ext;
}

AuthorityKeyIdentifierGenerateExt
X509v3CertificateIssueExts::getAuthorityKeyIdentifier() const
{
	return m_impl->authorityKeyIdentifier;
}

AuthorityKeyIdentifierGenerateExt&
X509v3CertificateIssueExts::authorityKeyIdentifier()
{
	return m_impl->authorityKeyIdentifier;
}

void
X509v3CertificateIssueExts::setSubjectAlternativeName(const SubjectAlternativeNameExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(limal::ValueException, 
		             "X509v3CertificateIssueExts::setSubjectAlternativeName invalid value");
	}
	m_impl->subjectAlternativeName = ext;
}

SubjectAlternativeNameExt
X509v3CertificateIssueExts::getSubjectAlternativeName() const
{
	return m_impl->subjectAlternativeName;
}

SubjectAlternativeNameExt&
X509v3CertificateIssueExts::subjectAlternativeName()
{
	return m_impl->subjectAlternativeName;
}

void
X509v3CertificateIssueExts::setIssuerAlternativeName(const IssuerAlternativeNameExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(limal::ValueException, 
		             "X509v3CertificateIssueExts::setIssuerAlternativeName invalid value");
	}
	m_impl->issuerAlternativeName = ext;
}

IssuerAlternativeNameExt
X509v3CertificateIssueExts::getIssuerAlternativeName() const
{
	return m_impl->issuerAlternativeName;
}

IssuerAlternativeNameExt&
X509v3CertificateIssueExts::issuerAlternativeName()
{
	return m_impl->issuerAlternativeName;
}

void
X509v3CertificateIssueExts::setAuthorityInfoAccess(const AuthorityInfoAccessExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(limal::ValueException, 
		             "X509v3CertificateIssueExts::setAuthorityInfoAccess invalid value");
	}
	m_impl->authorityInfoAccess = ext;
}

AuthorityInfoAccessExt
X509v3CertificateIssueExts::getAuthorityInfoAccess() const
{
	return m_impl->authorityInfoAccess;
}

AuthorityInfoAccessExt&
X509v3CertificateIssueExts::authorityInfoAccess()
{
	return m_impl->authorityInfoAccess;
}

void
X509v3CertificateIssueExts::setCRLDistributionPoints(const CRLDistributionPointsExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(limal::ValueException, 
		             "X509v3CertificateIssueExts::setCRLDistributionPoints invalid value");
	}
	m_impl->crlDistributionPoints = ext;
}

CRLDistributionPointsExt
X509v3CertificateIssueExts::getCRLDistributionPoints() const
{
	return m_impl->crlDistributionPoints;
}

CRLDistributionPointsExt&
X509v3CertificateIssueExts::crlDistributionPoints()
{
	return m_impl->crlDistributionPoints;
}

void
X509v3CertificateIssueExts::setCertificatePolicies(const CertificatePoliciesExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(limal::ValueException, 
		             "X509v3CertificateIssueExts::setCertificatePolicies invalid value");
	}
	m_impl->certificatePolicies = ext;
}

CertificatePoliciesExt
X509v3CertificateIssueExts::getCertificatePolicies() const
{
	return m_impl->certificatePolicies;
}

CertificatePoliciesExt&
X509v3CertificateIssueExts::certificatePolicies()
{
	return m_impl->certificatePolicies;
}

void
X509v3CertificateIssueExts::commit2Config(CA& ca, Type type) const
{
	if(!valid())
	{
		LOGIT_ERROR("invalid X509v3RequestExts object");
		BLOCXX_THROW(limal::ValueException, "invalid X509v3RequestExts object");
	}

	m_impl->nsBaseUrl.commit2Config(ca, type);
	m_impl->nsRevocationUrl.commit2Config(ca, type);
	m_impl->nsCaRevocationUrl.commit2Config(ca, type);
	m_impl->nsRenewalUrl.commit2Config(ca, type);
	m_impl->nsCaPolicyUrl.commit2Config(ca, type);
	m_impl->nsSslServerName.commit2Config(ca, type);
	m_impl->nsComment.commit2Config(ca, type);
	m_impl->keyUsage.commit2Config(ca, type);
	m_impl->nsCertType.commit2Config(ca, type);
	m_impl->basicConstraints.commit2Config(ca, type);
	m_impl->extendedKeyUsage.commit2Config(ca, type);
	m_impl->subjectKeyIdentifier.commit2Config(ca, type);
	m_impl->authorityKeyIdentifier.commit2Config(ca, type);
	m_impl->subjectAlternativeName.commit2Config(ca, type);
	m_impl->issuerAlternativeName.commit2Config(ca, type);
	m_impl->authorityInfoAccess.commit2Config(ca, type);
	m_impl->crlDistributionPoints.commit2Config(ca, type);
	m_impl->certificatePolicies.commit2Config(ca, type);
}

bool
X509v3CertificateIssueExts::valid() const
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

blocxx::StringArray
X509v3CertificateIssueExts::verify() const
{
	StringArray result;

	result.appendArray(m_impl->nsBaseUrl.verify());
	result.appendArray(m_impl->nsRevocationUrl.verify());
	result.appendArray(m_impl->nsCaRevocationUrl.verify());
	result.appendArray(m_impl->nsRenewalUrl.verify());
	result.appendArray(m_impl->nsCaPolicyUrl.verify());
	result.appendArray(m_impl->nsSslServerName.verify());
	result.appendArray(m_impl->nsComment.verify());
	result.appendArray(m_impl->keyUsage.verify());  
	result.appendArray(m_impl->nsCertType.verify());   
	result.appendArray(m_impl->basicConstraints.verify()); 
	result.appendArray(m_impl->extendedKeyUsage.verify());
	result.appendArray(m_impl->subjectKeyIdentifier.verify());
	result.appendArray(m_impl->authorityKeyIdentifier.verify());
	result.appendArray(m_impl->subjectAlternativeName.verify());
	result.appendArray(m_impl->issuerAlternativeName.verify());
	result.appendArray(m_impl->authorityInfoAccess.verify());
	result.appendArray(m_impl->crlDistributionPoints.verify());
	result.appendArray(m_impl->certificatePolicies.verify());

	LOGIT_DEBUG_STRINGARRAY("X509v3CertificateIssueExts::verify()", result);
	return result;
}

blocxx::StringArray
X509v3CertificateIssueExts::dump() const
{
	StringArray result;
	result.append("X509v3CertificateIssueExts::dump()");

	result.appendArray(m_impl->nsBaseUrl.dump());
	result.appendArray(m_impl->nsRevocationUrl.dump());
	result.appendArray(m_impl->nsCaRevocationUrl.dump());
	result.appendArray(m_impl->nsRenewalUrl.dump());
	result.appendArray(m_impl->nsCaPolicyUrl.dump());
	result.appendArray(m_impl->nsSslServerName.dump());
	result.appendArray(m_impl->nsComment.dump());
	result.appendArray(m_impl->keyUsage.dump());  
	result.appendArray(m_impl->nsCertType.dump());   
	result.appendArray(m_impl->basicConstraints.dump()); 
	result.appendArray(m_impl->extendedKeyUsage.dump());
	result.appendArray(m_impl->subjectKeyIdentifier.dump());
	result.appendArray(m_impl->authorityKeyIdentifier.dump());
	result.appendArray(m_impl->subjectAlternativeName.dump());
	result.appendArray(m_impl->issuerAlternativeName.dump());
	result.appendArray(m_impl->authorityInfoAccess.dump());
	result.appendArray(m_impl->crlDistributionPoints.dump());
	result.appendArray(m_impl->certificatePolicies.dump());

	return result;
}

}
}
