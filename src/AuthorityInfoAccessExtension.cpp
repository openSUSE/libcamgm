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

  File:       AuthorityInfoAccessExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/AuthorityInfoAccessExtension.hpp>
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>
#include  <blocxx/COWIntrusiveCountableBase.hpp>

#include  "Utils.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;


class AuthorityInformationImpl : public blocxx::COWIntrusiveCountableBase
{
	public:

	AuthorityInformationImpl()
		: accessOID(String()), location(LiteralValue())
	{}

	AuthorityInformationImpl(const String &accessOID_, 
	                         const LiteralValue& location_ )
		: accessOID(accessOID_), location(location_)
	{}
	
	AuthorityInformationImpl(const AuthorityInformationImpl &ai)
		: blocxx::COWIntrusiveCountableBase(ai),
		  accessOID(ai.accessOID),
		  location(ai.location)
	{}
	
	virtual ~AuthorityInformationImpl() {}
	
	AuthorityInformationImpl* clone() const
	{
		return new AuthorityInformationImpl(*this);
	}
	
	String                  accessOID;
	LiteralValue            location;

};

class AuthorityInfoAccessExtImpl : public blocxx::COWIntrusiveCountableBase
{
	public:
	AuthorityInfoAccessExtImpl()
		: info(blocxx::List<AuthorityInformation>())
	{}

	AuthorityInfoAccessExtImpl(const AuthorityInfoAccessExtImpl &aie)
		: blocxx::COWIntrusiveCountableBase(aie),
		  info(aie.info)
	{}

	virtual ~AuthorityInfoAccessExtImpl() {}

	AuthorityInfoAccessExtImpl* clone() const
	{
		return new AuthorityInfoAccessExtImpl(*this);
	}
	
	blocxx::List<AuthorityInformation> info;
};

	
AuthorityInformation::AuthorityInformation()
	: m_impl(new AuthorityInformationImpl())
{}

AuthorityInformation::AuthorityInformation(const AuthorityInformation& ai)
	: m_impl(ai.m_impl)
{}

AuthorityInformation::AuthorityInformation(const String &accessOID, 
                                           const LiteralValue& location)
	: m_impl(new AuthorityInformationImpl(accessOID, location))
{
	if(!location.valid())
	{
		LOGIT_ERROR("invalid location"); 
		BLOCXX_THROW(limal::ValueException, __("Invalid location."));
	}
	if(!initAccessOIDCheck().isValid(accessOID))
	{
		LOGIT_ERROR("invalid accessOID"); 
		BLOCXX_THROW(limal::ValueException, __("Invalid accessOID."));
	}
}

AuthorityInformation::~AuthorityInformation()
{}

AuthorityInformation&
AuthorityInformation::operator=(const AuthorityInformation& ai)
{
	if(this == &ai) return *this;
	
	m_impl = ai.m_impl;
	
	return *this;
}

void
AuthorityInformation::setAuthorityInformation(const String &accessOID, 
                                              const LiteralValue& location)
{
	if(!location.valid())
	{
		LOGIT_ERROR("invalid location"); 
		BLOCXX_THROW(limal::ValueException, __("Invalid location."));
	}
	if(!initAccessOIDCheck().isValid(accessOID))
	{
		LOGIT_ERROR("invalid accessOID"); 
		BLOCXX_THROW(limal::ValueException, __("Invalid accessOID."));
	}

	m_impl->accessOID = accessOID;
	m_impl->location  = location;
}

blocxx::String
AuthorityInformation::getAccessOID() const
{
	return m_impl->accessOID;
}

LiteralValue
AuthorityInformation::getLocation() const
{
	return m_impl->location;
}

bool
AuthorityInformation::valid() const
{
	if(!initAccessOIDCheck().isValid(m_impl->accessOID))
	{
		LOGIT_DEBUG("return AuthorityInformation::valid() is false"); 
		return false;
	}
	
	if(!m_impl->location.valid())
	{
		LOGIT_DEBUG("return AuthorityInformation::valid() is false"); 
		return false;
	}
	
	LOGIT_DEBUG("return AuthorityInformation::valid() is true"); 
	return true;
}

blocxx::StringArray
AuthorityInformation::verify() const
{
	StringArray result;
    
	if(!initAccessOIDCheck().isValid(m_impl->accessOID))
	{
		result.append(Format("invalid value(%1) for accessOID", m_impl->accessOID).toString());
	}
	result.appendArray(m_impl->location.verify());
    
	LOGIT_DEBUG_STRINGARRAY("AuthorityInformation::verify()", result);
	return result;
}

blocxx::StringArray
AuthorityInformation::dump() const
{
	StringArray result;
	result.append("AuthorityInformation::dump()");

	result.append("accessOID = " + getAccessOID());
	result.appendArray(getLocation().dump());

	return result;
}

// ------------------------------------------
// friends
// ------------------------------------------

bool
operator==(const AuthorityInformation &l, const AuthorityInformation &r)
{
	if(l.getAccessOID() == r.getAccessOID() &&
	   l.getLocation()  == r.getLocation() )
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool
operator<(const AuthorityInformation &l, const AuthorityInformation &r)
{
	if(l.getAccessOID() < r.getAccessOID() ||
	   l.getLocation()  < r.getLocation() )
	{
		return true;
	}
	else
	{
		return false;
	}
}

// ###############################################################################

AuthorityInfoAccessExt::AuthorityInfoAccessExt()
	: ExtensionBase(), m_impl(new AuthorityInfoAccessExtImpl())
{}

AuthorityInfoAccessExt::AuthorityInfoAccessExt(const AuthorityInfoAccessExt& extension)
    : ExtensionBase(extension), m_impl(extension.m_impl)
{}

AuthorityInfoAccessExt::AuthorityInfoAccessExt(CAConfig* caConfig, Type type)
	: ExtensionBase(), m_impl(new AuthorityInfoAccessExtImpl())
{
	// These types are not supported by this object
	if(type == E_Client_Req || type == E_Server_Req ||
	   type == E_CA_Req     || type == E_CRL           )
	{
		LOGIT_ERROR("wrong type" << type);
		BLOCXX_THROW(limal::ValueException, Format(__("Wrong type: %1."), type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, true), "authorityInfoAccess");
	if(p)
	{
		StringArray   sp   = PerlRegEx("\\s*,\\s*")
			.split(caConfig->getValue(type2Section(type, true), "authorityInfoAccess"));
		
		if(sp[0].equalsIgnoreCase("critical"))  setCritical(true);

		StringArray::const_iterator it = sp.begin();
		for(; it != sp.end(); ++it)
		{
			StringArray al = PerlRegEx(";").split(*it);

			try
			{
				AuthorityInformation ai = AuthorityInformation(al[0], LiteralValue(al[1]));
				m_impl->info.push_back(ai);
			}
			catch(blocxx::Exception& e)
			{
				LOGIT_ERROR("invalid value: " << *it << "(" << al[0] << "/" << al[1] << ")");
			}
		}
	}
	setPresent(p);
}

AuthorityInfoAccessExt::~AuthorityInfoAccessExt() {}

AuthorityInfoAccessExt& 
AuthorityInfoAccessExt::operator=(const AuthorityInfoAccessExt& extension)
{
	if(this == &extension) return *this;
    
	ExtensionBase::operator=(extension);
	m_impl = extension.m_impl;

	return *this;
}

void
AuthorityInfoAccessExt::setAuthorityInformation(const blocxx::List<AuthorityInformation>& infolist)
{
	blocxx::List<AuthorityInformation>::const_iterator it = infolist.begin();
	for(;it != infolist.end(); it++) {
		if(!(*it).valid()) {
			LOGIT_ERROR("invalid AuthorityInformation in infolist");
			BLOCXX_THROW(limal::ValueException,
			             __("Invalid AuthorityInformation in the information list."));
		}
	}
	setPresent(true);
	m_impl->info = infolist;
}

blocxx::List<AuthorityInformation>
AuthorityInfoAccessExt::getAuthorityInformation() const
{
	if(!isPresent()) {
		LOGIT_ERROR("AuthorityInfoAccessExt is not present");
		BLOCXX_THROW(limal::RuntimeException,
		             __("AuthorityInfoAccessExt is not present."));
	}
	return m_impl->info;
}

void 
AuthorityInfoAccessExt::commit2Config(CA& ca, Type type) const
{
	if(!valid())
	{
		LOGIT_ERROR("invalid AuthorityInfoAccessExt object");
		BLOCXX_THROW(limal::ValueException, __("Invalid AuthorityInfoAccessExt object."));
	}

	// These types are not supported by this object
	if(type == E_Client_Req || type == E_Server_Req ||
	   type == E_CA_Req     || type == E_CRL           )
	{
		LOGIT_ERROR("wrong type" << type);
		BLOCXX_THROW(limal::ValueException, Format(__("Wrong type: %1."), type).c_str());
	}

	if(isPresent())
	{
		String extString;

		if(isCritical()) extString += "critical,";

		String val;
		blocxx::List<AuthorityInformation>::const_iterator it = m_impl->info.begin();
		for(;it != m_impl->info.end(); ++it)
		{
			val = "";
			if( (val = (*it).getLocation().commit2Config(ca, type, 0)) != "")
			{
				extString += (*it).getAccessOID() + ";" + val +",";
			}
		}

		ca.getConfig()->setValue(type2Section(type, true), "authorityInfoAccess",
		                         extString.erase(extString.length()-1));
	} else {
		ca.getConfig()->deleteValue(type2Section(type, true), "authorityInfoAccess");
	}
}

bool
AuthorityInfoAccessExt::valid() const
{
	if(!isPresent())
	{
		LOGIT_DEBUG("return AuthorityInfoAccessExt::valid() is true");
		return true;
	}

	if(m_impl->info.empty())
	{
		LOGIT_DEBUG("return AuthorityInfoAccessExt::valid() is false");
		return false;
	}
	blocxx::List<AuthorityInformation>::const_iterator it = m_impl->info.begin();
	for(;it != m_impl->info.end(); it++)
	{
		if(!(*it).valid())
		{
			LOGIT_DEBUG("return AuthorityInfoAccessExt::valid() is false");
			return false;
		}
	}
	LOGIT_DEBUG("return AuthorityInfoAccessExt::valid() is true");
	return true;
}

blocxx::StringArray
AuthorityInfoAccessExt::verify() const
{
	blocxx::StringArray result;

	if(!isPresent()) return result;
    
	if(m_impl->info.empty())
	{
		result.append(String("No access informations available"));
	}
	blocxx::List<AuthorityInformation>::const_iterator it = m_impl->info.begin();
	for(;it != m_impl->info.end(); it++)
	{
		result.appendArray((*it).verify());
	}

	LOGIT_DEBUG_STRINGARRAY("AuthorityInfoAccessExt::verify()", result);
	return result;
}

blocxx::StringArray
AuthorityInfoAccessExt::dump() const
{
	StringArray result;
	result.append("AuthorityInfoAccessExt::dump()");

	result.appendArray(ExtensionBase::dump());
	if(!isPresent()) return result;

	blocxx::List< AuthorityInformation >::const_iterator it = m_impl->info.begin();
	for(; it != m_impl->info.end(); ++it)
	{
		result.appendArray((*it).dump());
	}
	return result;
}

}
}
