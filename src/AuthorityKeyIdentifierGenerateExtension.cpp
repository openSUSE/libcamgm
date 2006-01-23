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

  File:       AuthorityKeyIdentifierGenerateExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/AuthorityKeyIdentifierGenerateExtension.hpp>
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

class AuthorityKeyIdentifierGenerateExtImpl : public blocxx::COWIntrusiveCountableBase
{
	public:

	AuthorityKeyIdentifierGenerateExtImpl()
		: keyid(AuthorityKeyIdentifierGenerateExt::KeyID_none)
		, issuer(AuthorityKeyIdentifierGenerateExt::Issuer_none)
	{}

	AuthorityKeyIdentifierGenerateExtImpl(AuthorityKeyIdentifierGenerateExt::KeyID ki,
	                                      AuthorityKeyIdentifierGenerateExt::Issuer is)
		: keyid(ki)
		, issuer(is)
	{}

	AuthorityKeyIdentifierGenerateExtImpl(const AuthorityKeyIdentifierGenerateExtImpl& impl)
		: COWIntrusiveCountableBase(impl)
		, keyid(impl.keyid)
		, issuer(impl.issuer)
	{}
	
	~AuthorityKeyIdentifierGenerateExtImpl() {}

	AuthorityKeyIdentifierGenerateExtImpl* clone() const
	{
		return new AuthorityKeyIdentifierGenerateExtImpl(*this);
	}
	
	AuthorityKeyIdentifierGenerateExt::KeyID  keyid;
	AuthorityKeyIdentifierGenerateExt::Issuer issuer; 

};


AuthorityKeyIdentifierGenerateExt::AuthorityKeyIdentifierGenerateExt()
	: ExtensionBase()
	, m_impl(new AuthorityKeyIdentifierGenerateExtImpl())
{}

AuthorityKeyIdentifierGenerateExt::AuthorityKeyIdentifierGenerateExt(CAConfig* caConfig,
                                                                     Type type)
	: ExtensionBase()
	, m_impl(new AuthorityKeyIdentifierGenerateExtImpl())
{
	// These types are not supported by this object
	if(type == E_Client_Req || type == E_Server_Req || type == E_CA_Req)
	{
		LOGIT_ERROR("wrong type" << type);
		BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, true), "authorityKeyIdentifier");
	if(p)
	{
		StringArray   sp   = PerlRegEx("\\s*,\\s*")
			.split(caConfig->getValue(type2Section(type, true), "authorityKeyIdentifier"));
		if(sp[0].equalsIgnoreCase("critical"))
		{
			setCritical(true);
			sp.remove(0);
		}

		StringArray::const_iterator it = sp.begin();
		for(; it != sp.end(); ++it)
		{
			if((*it).equalsIgnoreCase("keyid")) m_impl->keyid = KeyID_normal;
			else if((*it).equalsIgnoreCase("keyid:always")) m_impl->keyid = KeyID_always;
			else if((*it).equalsIgnoreCase("issuer")) m_impl->issuer = Issuer_normal;
			else if((*it).equalsIgnoreCase("issuer:always")) m_impl->issuer = Issuer_always;
		}
	}
	setPresent(p);
}

AuthorityKeyIdentifierGenerateExt::AuthorityKeyIdentifierGenerateExt(KeyID kid,
                                                                     Issuer iss)
	: ExtensionBase()
	, m_impl(new AuthorityKeyIdentifierGenerateExtImpl(kid, iss))
{
	setPresent(true);
}

AuthorityKeyIdentifierGenerateExt::AuthorityKeyIdentifierGenerateExt(const AuthorityKeyIdentifierGenerateExt& extension)
	: ExtensionBase(extension)
	, m_impl(extension.m_impl)
{}

AuthorityKeyIdentifierGenerateExt::~AuthorityKeyIdentifierGenerateExt()
{}


AuthorityKeyIdentifierGenerateExt& 
AuthorityKeyIdentifierGenerateExt::operator=(const AuthorityKeyIdentifierGenerateExt& extension)
{
	if(this == &extension) return *this;

	ExtensionBase::operator=(extension);
	m_impl = extension.m_impl;
    
	return *this;
}

void
AuthorityKeyIdentifierGenerateExt::setKeyID(KeyID kid)
{
	m_impl->keyid = kid;
	setPresent(true);
}

AuthorityKeyIdentifierGenerateExt::KeyID
AuthorityKeyIdentifierGenerateExt::getKeyID() const
{
	if(!isPresent())
	{
		LOGIT_ERROR("AuthorityKeyIdentifierGenerateExt is not present");
		BLOCXX_THROW(limal::RuntimeException,
		             "AuthorityKeyIdentifierGenerateExt is not present");
	}
	return m_impl->keyid;
}

void
AuthorityKeyIdentifierGenerateExt::setIssuer(Issuer iss)
{
	m_impl->issuer = iss;
	setPresent(true);
}

AuthorityKeyIdentifierGenerateExt::Issuer
AuthorityKeyIdentifierGenerateExt::getIssuer() const
{
	if(!isPresent())
	{
		LOGIT_ERROR("AuthorityKeyIdentifierGenerateExt is not present");
		BLOCXX_THROW(limal::RuntimeException,
		             "AuthorityKeyIdentifierGenerateExt is not present");
	}
	return m_impl->issuer;
}

void
AuthorityKeyIdentifierGenerateExt::commit2Config(CA& ca, Type type) const
{
	if(!valid())
	{
		LOGIT_ERROR("invalid AuthorityKeyIdentifierGenerateExt object");
		BLOCXX_THROW(limal::ValueException,
		             "invalid AuthorityKeyIdentifierGenerateExt object");
	}

	// These types are not supported by this object
	if(type == E_Client_Req || type == E_Server_Req || type == E_CA_Req)
	{
		LOGIT_ERROR("wrong type" << type);
		BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
	}

	if(isPresent())
	{
		String extString;

		if(isCritical()) extString += "critical,";

		switch(getKeyID())
		{
			case AuthorityKeyIdentifierGenerateExt::KeyID_normal:
				extString += "keyid,";
				break;
			case AuthorityKeyIdentifierGenerateExt::KeyID_always:
				extString += "keyid:always,";
				break;
			default:
				break;
		}

		switch(getIssuer())
		{
			case AuthorityKeyIdentifierGenerateExt::Issuer_normal:
				extString += "issuer,";
				break;
			case AuthorityKeyIdentifierGenerateExt::Issuer_always:
				extString += "issuer:always,";
				break;
			default:
				break;
		}

		ca.getConfig()->setValue(type2Section(type, true), "authorityKeyIdentifier",
		                         extString.erase(extString.length()-1));
	}
	else
	{
		ca.getConfig()->deleteValue(type2Section(type, true), "authorityKeyIdentifier");
	}
}

bool
AuthorityKeyIdentifierGenerateExt::valid() const
{
	if(!isPresent())
	{
		LOGIT_DEBUG("return AuthorityKeyIdentifierGenerateExt::valid() is true");
		return true;
	}
	if(getKeyID() == KeyID_none && getIssuer() == Issuer_none)
	{
		LOGIT_DEBUG("return AuthorityKeyIdentifierGenerateExt::valid() is false");
		return false;
	}
	LOGIT_DEBUG("return AuthorityKeyIdentifierGenerateExt::valid() is true");
	return true;
}

blocxx::StringArray
AuthorityKeyIdentifierGenerateExt::verify() const
{
	blocxx::StringArray result;

	if(!isPresent()) return result;
	if(getKeyID() == KeyID_none && getIssuer() == Issuer_none)
	{
		result.append(String("Invalid value for keyid and issuer. ") +
		              String("At least one of both must be set"));
	}
	LOGIT_DEBUG_STRINGARRAY("AuthorityKeyIdentifierGenerateExt::verify()", result);
	return result;
}

blocxx::StringArray
AuthorityKeyIdentifierGenerateExt::dump() const
{
	StringArray result;
	result.append("AuthorityKeyIdentifierGenerateExt::dump()");

	result.appendArray(ExtensionBase::dump());
	if(!isPresent()) return result;

	result.append("KeyID = " + String(getKeyID()));
	result.append("Issuer = " + String(getIssuer()));

	return result;
}

}
}
