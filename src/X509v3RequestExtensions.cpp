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

  File:       X509v3RequestExtensions.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/X509v3RequestExtensions.hpp>
#include  <limal/Exception.hpp>


#include  "X509v3RequestExtensionsImpl.hpp"
#include  "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;
using namespace blocxx;


X509v3RequestExts::X509v3RequestExts()
	: m_impl(new X509v3RequestExtsImpl())
{}

X509v3RequestExts::X509v3RequestExts(CAConfig* caConfig, Type type)
	: m_impl(new X509v3RequestExtsImpl(caConfig, type))
{}

X509v3RequestExts::X509v3RequestExts(const X509v3RequestExts& extensions)
	: m_impl(extensions.m_impl)
{}

X509v3RequestExts::~X509v3RequestExts()
{}

X509v3RequestExts&
X509v3RequestExts::operator=(const X509v3RequestExts& extensions)
{
	if(this == &extensions) return *this;

	m_impl = extensions.m_impl;

	return *this;
}

void
X509v3RequestExts::setNsSslServerName(const NsSslServerNameExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("Invalid value for X509v3RequestExts::setNsSslServerName."));
	}
	m_impl->nsSslServerName = ext;
}

NsSslServerNameExt
X509v3RequestExts::getNsSslServerName() const
{
	return m_impl->nsSslServerName;
}

NsSslServerNameExt&
X509v3RequestExts::nsSslServerName()
{
	return m_impl->nsSslServerName;
}

void
X509v3RequestExts::setNsComment(const NsCommentExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("Invalid value for X509v3RequestExts::setNsComment."));
	}
	m_impl->nsComment = ext;
}

NsCommentExt
X509v3RequestExts::getNsComment() const
{
	return m_impl->nsComment;
}

NsCommentExt&
X509v3RequestExts::nsComment()
{
	return m_impl->nsComment;
}

void
X509v3RequestExts::setNsCertType(const NsCertTypeExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("Invalid value for X509v3RequestExts::setNsCertType."));
	}
	m_impl->nsCertType = ext;
}

NsCertTypeExt
X509v3RequestExts::getNsCertType() const
{
	return m_impl->nsCertType;
}

NsCertTypeExt&
X509v3RequestExts::nsCertType()
{
	return m_impl->nsCertType;
}

void
X509v3RequestExts::setKeyUsage(const KeyUsageExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("Invalid value for X509v3RequestExts::setKeyUsage."));
	}
	m_impl->keyUsage = ext;
}

KeyUsageExt
X509v3RequestExts::getKeyUsage() const
{
	return m_impl->keyUsage;
}

KeyUsageExt&
X509v3RequestExts::keyUsage()
{
	return m_impl->keyUsage;
}

void
X509v3RequestExts::setBasicConstraints(const BasicConstraintsExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("Invalid value for X509v3RequestExts::setBasicConstraints."));
	}
	m_impl->basicConstraints = ext;
}

BasicConstraintsExt
X509v3RequestExts::getBasicConstraints() const
{
	return m_impl->basicConstraints;
}

BasicConstraintsExt&
X509v3RequestExts::basicConstraints()
{
	return m_impl->basicConstraints;
}

void
X509v3RequestExts::setExtendedKeyUsage(const ExtendedKeyUsageExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("Invalid value for X509v3RequestExts::setExtendedKeyUsage."));
	}
	m_impl->extendedKeyUsage = ext;
}

ExtendedKeyUsageExt
X509v3RequestExts::getExtendedKeyUsage() const
{
	return m_impl->extendedKeyUsage;
}

ExtendedKeyUsageExt&
X509v3RequestExts::extendedKeyUsage()
{
	return m_impl->extendedKeyUsage;
}

void
X509v3RequestExts::setSubjectKeyIdentifier(const SubjectKeyIdentifierExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("Invalid value for X509v3RequestExts::setSubjectKeyIdentifier."));
	}
	m_impl->subjectKeyIdentifier = ext;
}

SubjectKeyIdentifierExt
X509v3RequestExts::getSubjectKeyIdentifier() const
{
	return m_impl->subjectKeyIdentifier;
}

SubjectKeyIdentifierExt&
X509v3RequestExts::subjectKeyIdentifier()
{
	return m_impl->subjectKeyIdentifier;
}

void
X509v3RequestExts::setSubjectAlternativeName(const SubjectAlternativeNameExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("Invalid value for X509v3RequestExts::setSubjectAlternativeName."));
	}
	m_impl->subjectAlternativeName = ext;
}

SubjectAlternativeNameExt
X509v3RequestExts::getSubjectAlternativeName() const
{
	return m_impl->subjectAlternativeName;
}

SubjectAlternativeNameExt&
X509v3RequestExts::subjectAlternativeName()
{
	return m_impl->subjectAlternativeName;
}

void
X509v3RequestExts::commit2Config(CA& ca, Type type) const
{
	if(!valid())
	{
		LOGIT_ERROR("invalid X509v3RequestExts object");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("Invalid X509v3RequestExts object."));
	}
	m_impl->nsSslServerName.commit2Config(ca, type);
	m_impl->nsComment.commit2Config(ca, type);
	m_impl->keyUsage.commit2Config(ca, type);
	m_impl->nsCertType.commit2Config(ca, type);
	m_impl->basicConstraints.commit2Config(ca, type);
	m_impl->extendedKeyUsage.commit2Config(ca, type);
	m_impl->subjectKeyIdentifier.commit2Config(ca, type);
	m_impl->subjectAlternativeName.commit2Config(ca, type);
}

bool
X509v3RequestExts::valid() const
{
	if(!m_impl->nsSslServerName.valid()) return false;
	if(!m_impl->nsComment.valid()) return false;
	if(!m_impl->keyUsage.valid()) return false;
	if(!m_impl->nsCertType.valid()) return false;
	if(!m_impl->basicConstraints.valid()) return false;
	if(!m_impl->extendedKeyUsage.valid()) return false;
	if(!m_impl->subjectKeyIdentifier.valid()) return false;
	if(!m_impl->subjectAlternativeName.valid()) return false;
	return true;
}

std::vector<std::string>
X509v3RequestExts::verify() const
{
	std::vector<std::string> result;

	appendArray(result, m_impl->nsSslServerName.verify());
	appendArray(result, m_impl->nsComment.verify());
	appendArray(result, m_impl->keyUsage.verify());
	appendArray(result, m_impl->nsCertType.verify());
	appendArray(result, m_impl->basicConstraints.verify());
	appendArray(result, m_impl->extendedKeyUsage.verify());
	appendArray(result, m_impl->subjectKeyIdentifier.verify());
	appendArray(result, m_impl->subjectAlternativeName.verify());

	LOGIT_DEBUG_STRINGARRAY("X509v3RequestExts::verify()", result);
	return result;
}

std::vector<std::string>
X509v3RequestExts::dump() const
{
	std::vector<std::string> result;
	result.push_back("X509v3RequestExts::dump()");

	appendArray(result, m_impl->nsSslServerName.dump());
	appendArray(result, m_impl->nsComment.dump());
	appendArray(result, m_impl->keyUsage.dump());
	appendArray(result, m_impl->nsCertType.dump());
	appendArray(result, m_impl->basicConstraints.dump());
	appendArray(result, m_impl->extendedKeyUsage.dump());
	appendArray(result, m_impl->subjectKeyIdentifier.dump());
	appendArray(result, m_impl->subjectAlternativeName.dump());

	return result;
}

}
