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

  File:       X509v3CRLGenerationExtensions.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/


#include  <limal/ca-mgm/X509v3CRLGenerationExtensions.hpp>
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

class X509v3CRLGenerationExtsImpl : public blocxx::COWIntrusiveCountableBase
{
	public:
	X509v3CRLGenerationExtsImpl()
		: authorityKeyIdentifier(AuthorityKeyIdentifierGenerateExt()),
		  issuerAlternativeName(IssuerAlternativeNameExt())
 
	{}

	X509v3CRLGenerationExtsImpl(CAConfig* caConfig, Type type)
		: authorityKeyIdentifier(caConfig, type),
		  issuerAlternativeName(caConfig, type)
	{}

	X509v3CRLGenerationExtsImpl(const X509v3CRLGenerationExtsImpl& impl)
		: COWIntrusiveCountableBase(impl),
		  authorityKeyIdentifier(impl.authorityKeyIdentifier),
		  issuerAlternativeName(impl.issuerAlternativeName)
	{}

	~X509v3CRLGenerationExtsImpl() {}

	X509v3CRLGenerationExtsImpl* clone() const
	{
		return new X509v3CRLGenerationExtsImpl(*this);
	}

	AuthorityKeyIdentifierGenerateExt authorityKeyIdentifier;
	IssuerAlternativeNameExt          issuerAlternativeName;
};

	
X509v3CRLGenerationExts::X509v3CRLGenerationExts()
	: m_impl(new X509v3CRLGenerationExtsImpl())
{}

X509v3CRLGenerationExts::X509v3CRLGenerationExts(CAConfig* caConfig, Type type)
	: m_impl(new X509v3CRLGenerationExtsImpl(caConfig, type))
{}

X509v3CRLGenerationExts::X509v3CRLGenerationExts(const X509v3CRLGenerationExts& extensions)
	: m_impl(extensions.m_impl)
{}

X509v3CRLGenerationExts::~X509v3CRLGenerationExts()
{}

X509v3CRLGenerationExts&
X509v3CRLGenerationExts::operator=(const X509v3CRLGenerationExts& extension)
{
	if(this == &extension) return *this;
    
	m_impl = extension.m_impl;
    
	return *this;
}

void
X509v3CRLGenerationExts::setAuthorityKeyIdentifier(const AuthorityKeyIdentifierGenerateExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(limal::ValueException, 
		             __("Invalid value for X509v3CRLGenerationExts::setAuthorityKeyIdentifier."));
	}
	m_impl->authorityKeyIdentifier = ext;
}

AuthorityKeyIdentifierGenerateExt
X509v3CRLGenerationExts::getAuthorityKeyIdentifier() const
{
	return m_impl->authorityKeyIdentifier;
}

AuthorityKeyIdentifierGenerateExt&
X509v3CRLGenerationExts::authorityKeyIdentifier()
{
	return m_impl->authorityKeyIdentifier;
}

void
X509v3CRLGenerationExts::setIssuerAlternativeName(const IssuerAlternativeNameExt &ext)
{
	if(!ext.valid())
	{
		BLOCXX_THROW(limal::ValueException, 
		             __("Invalid value for X509v3CRLGenerationExts::setIssuerAlternativeName."));
	}
	m_impl->issuerAlternativeName = ext;
}

IssuerAlternativeNameExt
X509v3CRLGenerationExts::getIssuerAlternativeName() const
{
	return m_impl->issuerAlternativeName;
}

IssuerAlternativeNameExt&
X509v3CRLGenerationExts::issuerAlternativeName()
{
	return m_impl->issuerAlternativeName;
}

void
X509v3CRLGenerationExts::commit2Config(CA& ca, Type type) const
{
	if(!valid())
	{
		LOGIT_ERROR("invalid X509v3RequestExts object");
		BLOCXX_THROW(limal::ValueException,
		             __("Invalid X509v3RequestExts object."));
	}
    
	m_impl->authorityKeyIdentifier.commit2Config(ca, type);
	m_impl->issuerAlternativeName.commit2Config(ca, type);
}

bool
X509v3CRLGenerationExts::valid() const
{
	if(!m_impl->authorityKeyIdentifier.valid()) return false;
	if(!m_impl->issuerAlternativeName.valid())  return false;
	return true;
}

blocxx::StringArray
X509v3CRLGenerationExts::verify() const
{
	StringArray result;

	result.appendArray(m_impl->authorityKeyIdentifier.verify());
	result.appendArray(m_impl->issuerAlternativeName.verify());
    
	LOGIT_DEBUG_STRINGARRAY("X509v3CRLGenerationExts::verify()", result);
	return result;;
}

blocxx::StringArray
X509v3CRLGenerationExts::dump() const
{
	StringArray result;
	result.append("X509v3CRLGenerationExts::dump()");

	result.appendArray(m_impl->authorityKeyIdentifier.dump());
	result.appendArray(m_impl->issuerAlternativeName.dump());

	return result;
}

}
}
