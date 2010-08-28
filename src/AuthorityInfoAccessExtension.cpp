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

#include  <ca-mgm/AuthorityInfoAccessExtension.hpp>
#include  <ca-mgm/CA.hpp>
#include  <ca-mgm/ValueRegExCheck.hpp>
#include  <ca-mgm/Exception.hpp>



#include  "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;

class AuthorityInformationImpl
{
public:

	AuthorityInformationImpl()
		: accessOID(std::string()), location(LiteralValue())
	{}

	AuthorityInformationImpl(const std::string &accessOID_,
	                         const LiteralValue& location_ )
		: accessOID(accessOID_), location(location_)
	{}

	AuthorityInformationImpl(const AuthorityInformationImpl &ai)
		: accessOID(ai.accessOID)
		, location(ai.location)
	{}

	virtual ~AuthorityInformationImpl() {}

	AuthorityInformationImpl* clone() const
	{
		return new AuthorityInformationImpl(*this);
	}

	std::string             accessOID;
	LiteralValue            location;

};

class AuthorityInfoAccessExtImpl
{
public:
	AuthorityInfoAccessExtImpl()
		: info(std::list<AuthorityInformation>())
	{}

	AuthorityInfoAccessExtImpl(const AuthorityInfoAccessExtImpl &aie)
		: info(aie.info)
	{}

	virtual ~AuthorityInfoAccessExtImpl() {}

	AuthorityInfoAccessExtImpl* clone() const
	{
		return new AuthorityInfoAccessExtImpl(*this);
	}

	std::list<AuthorityInformation> info;
};


AuthorityInformation::AuthorityInformation()
	: m_impl(new AuthorityInformationImpl())
{}

AuthorityInformation::AuthorityInformation(const AuthorityInformation& ai)
	: m_impl(ai.m_impl)
{}

AuthorityInformation::AuthorityInformation(const std::string &accessOID,
                                           const LiteralValue& location)
	: m_impl(new AuthorityInformationImpl(accessOID, location))
{
	if(!location.valid())
	{
		LOGIT_ERROR("invalid location");
		CA_MGM_THROW(ca_mgm::ValueException, __("Invalid location."));
	}
	if(!initAccessOIDCheck().isValid(accessOID))
	{
		LOGIT_ERROR("invalid accessOID");
		CA_MGM_THROW(ca_mgm::ValueException, __("Invalid accessOID."));
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
AuthorityInformation::setAuthorityInformation(const std::string &accessOID,
                                              const LiteralValue& location)
{
	if(!location.valid())
	{
		LOGIT_ERROR("invalid location");
		CA_MGM_THROW(ca_mgm::ValueException, __("Invalid location."));
	}
	if(!initAccessOIDCheck().isValid(accessOID))
	{
		LOGIT_ERROR("invalid accessOID");
		CA_MGM_THROW(ca_mgm::ValueException, __("Invalid accessOID."));
	}

	m_impl->accessOID = accessOID;
	m_impl->location  = location;
}

std::string
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

std::vector<std::string>
AuthorityInformation::verify() const
{
	std::vector<std::string> result;

	if(!initAccessOIDCheck().isValid(m_impl->accessOID))
	{
		result.push_back(str::form("invalid value(%s) for accessOID", m_impl->accessOID.c_str()));
	}
	appendArray(result, m_impl->location.verify());

	LOGIT_DEBUG_STRINGARRAY("AuthorityInformation::verify()", result);
	return result;
}

std::vector<std::string>
AuthorityInformation::dump() const
{
	std::vector<std::string> result;
	result.push_back("AuthorityInformation::dump()");

	result.push_back("accessOID = " + getAccessOID());
	appendArray(result, getLocation().dump());

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
		CA_MGM_THROW(ca_mgm::ValueException, str::form(__("Wrong type: %1."), type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, true), "authorityInfoAccess");
	if(p)
	{
		std::vector<std::string>   sp   = PerlRegEx("\\s*,\\s*")
			.split(caConfig->getValue(type2Section(type, true), "authorityInfoAccess"));

		if(0 == str::compareCI(sp[0], "critical"))  setCritical(true);

		std::vector<std::string>::const_iterator it = sp.begin();
		for(; it != sp.end(); ++it)
		{
			std::vector<std::string> al = PerlRegEx(";").split(*it);

			try
			{
				AuthorityInformation ai = AuthorityInformation(al[0], LiteralValue(al[1]));
				m_impl->info.push_back(ai);
			}
			catch(ca_mgm::Exception& e)
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
AuthorityInfoAccessExt::setAuthorityInformation(const std::list<AuthorityInformation>& infolist)
{
	std::list<AuthorityInformation>::const_iterator it = infolist.begin();
	for(;it != infolist.end(); it++) {
		if(!(*it).valid()) {
			LOGIT_ERROR("invalid AuthorityInformation in infolist");
			CA_MGM_THROW(ca_mgm::ValueException,
			             __("Invalid AuthorityInformation in the information list."));
		}
	}
	setPresent(true);
	m_impl->info = infolist;
}

std::list<AuthorityInformation>
AuthorityInfoAccessExt::getAuthorityInformation() const
{
	if(!isPresent()) {
		LOGIT_ERROR("AuthorityInfoAccessExt is not present");
		CA_MGM_THROW(ca_mgm::RuntimeException,
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
		CA_MGM_THROW(ca_mgm::ValueException, __("Invalid AuthorityInfoAccessExt object."));
	}

	// These types are not supported by this object
	if(type == E_Client_Req || type == E_Server_Req ||
	   type == E_CA_Req     || type == E_CRL           )
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException, str::form(__("Wrong type: %1."), type).c_str());
	}

	if(isPresent())
	{
		std::string extString;

		if(isCritical()) extString += "critical,";

		std::string val;
		std::list<AuthorityInformation>::const_iterator it = m_impl->info.begin();
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
	std::list<AuthorityInformation>::const_iterator it = m_impl->info.begin();
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

std::vector<std::string>
AuthorityInfoAccessExt::verify() const
{
	std::vector<std::string> result;

	if(!isPresent()) return result;

	if(m_impl->info.empty())
	{
		result.push_back(std::string("No access informations available"));
	}
	std::list<AuthorityInformation>::const_iterator it = m_impl->info.begin();
	for(;it != m_impl->info.end(); it++)
	{
		appendArray(result, (*it).verify());
	}

	LOGIT_DEBUG_STRINGARRAY("AuthorityInfoAccessExt::verify()", result);
	return result;
}

std::vector<std::string>
AuthorityInfoAccessExt::dump() const
{
	std::vector<std::string> result;
	result.push_back("AuthorityInfoAccessExt::dump()");

	appendArray(result, ExtensionBase::dump());
	if(!isPresent()) return result;

	std::list< AuthorityInformation >::const_iterator it = m_impl->info.begin();
	for(; it != m_impl->info.end(); ++it)
	{
		appendArray(result, (*it).dump());
	}
	return result;
}

}
