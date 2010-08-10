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

  File:       ExtendedKeyUsageExt.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  <limal/ca-mgm/BitExtensions.hpp>
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>



#include "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;

class ExtendedKeyUsageExtImpl
{
public:
	ExtendedKeyUsageExtImpl()
		: usage(StringList())
	{}

	ExtendedKeyUsageExtImpl(const ExtendedKeyUsageExtImpl& impl)
		: usage(impl.usage)
	{}

	~ExtendedKeyUsageExtImpl() {}

	ExtendedKeyUsageExtImpl* clone() const
	{
		return new ExtendedKeyUsageExtImpl(*this);
	}

	StringList usage;
};

ExtendedKeyUsageExt::ExtendedKeyUsageExt()
	: ExtensionBase()
	, m_impl(new ExtendedKeyUsageExtImpl())
{}

ExtendedKeyUsageExt::ExtendedKeyUsageExt(CAConfig* caConfig, Type type)
	: ExtensionBase()
	, m_impl(new ExtendedKeyUsageExtImpl())
{
	LOGIT_DEBUG("Parse ExtendedKeyUsage");

	// These types are not supported by this object
	if(type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, true), "extendedKeyUsage");
	if(p)
	{
		std::string      ct    = caConfig->getValue(type2Section(type, true),
		                                       "extendedKeyUsage");
		std::vector<std::string> sp    = PerlRegEx("\\s*,\\s*").split(ct);

		std::vector<std::string>::const_iterator it = sp.begin();
		if(0 == str::compareCI(sp[0], "critical"))
		{
			setCritical(true);
			++it;             // ignore critical for further checks
		}

		for(; it != sp.end(); ++it)
		{
			if(checkValue(*it))
			{
				m_impl->usage.push_back(*it);
			}
			else
				LOGIT_INFO("Unknown ExtendedKeyUsage option: " << (*it));
		}
	}
	setPresent(p);
}

ExtendedKeyUsageExt::ExtendedKeyUsageExt(const StringList& extKeyUsages)
	: ExtensionBase()
	, m_impl(new ExtendedKeyUsageExtImpl())
{
	StringList::const_iterator it = extKeyUsages.begin();
	for(; it != extKeyUsages.end(); ++it)
	{
		if(checkValue(*it))
		{
			m_impl->usage.push_back(*it);
		}
		else
		{
			LOGIT_INFO("Unknown ExtendedKeyUsage option: " << (*it));
			CA_MGM_THROW(ca_mgm::ValueException,
			             str::form(__("Invalid ExtendedKeyUsage option %s."),
			                    (*it).c_str()).c_str());
		}
	}

	if(m_impl->usage.empty())
	{
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid ExtendedKeyUsageExt."));
	}

	setPresent(true);
}


ExtendedKeyUsageExt::ExtendedKeyUsageExt(const ExtendedKeyUsageExt& extension)
	: ExtensionBase(extension), m_impl(extension.m_impl)
{}

ExtendedKeyUsageExt::~ExtendedKeyUsageExt()
{}


ExtendedKeyUsageExt&
ExtendedKeyUsageExt::operator=(const ExtendedKeyUsageExt& extension)
{
	if(this == &extension) return *this;

	ExtensionBase::operator=(extension);
	m_impl = extension.m_impl;

	return *this;
}

void
ExtendedKeyUsageExt::setExtendedKeyUsage(const StringList& usageList)
{
	StringList::const_iterator it = usageList.begin();
	m_impl->usage.clear();
	for(; it != usageList.end(); ++it)
	{
		if(checkValue(*it))
		{
			m_impl->usage.push_back(*it);
		}
		else
		{
			LOGIT_INFO("Unknown ExtendedKeyUsage option: " << (*it));
			CA_MGM_THROW(ca_mgm::ValueException,
			             str::form(__("Invalid ExtendedKeyUsage option %s."),
			                    (*it).c_str()).c_str());
		}
	}

	if(m_impl->usage.empty())
	{
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid ExtendedKeyUsageExt."));
	}

	setPresent(true);
}


StringList
ExtendedKeyUsageExt::getExtendedKeyUsage() const
{
	if(!isPresent())
	{
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("ExtendedKeyUsageExt is not present."));
	}
	return m_impl->usage;
}

bool
ExtendedKeyUsageExt::isEnabledFor(const std::string& extKeyUsage) const
{
	// if ! isPresent() ... throw exceptions?
	if(!isPresent() || m_impl->usage.empty()) return false;

	StringList::const_iterator it = m_impl->usage.begin();
	for(;it != m_impl->usage.end(); ++it)
	{
		if(0 == str::compareCI(extKeyUsage, *it))
		{
			return true;
		}
	}
	return false;
}

void
ExtendedKeyUsageExt::commit2Config(CA& ca, Type type) const
{
	if(!valid())
	{
		LOGIT_ERROR("invalid ExtendedKeyUsageExt object");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid ExtendedKeyUsageExt object."));
	}

	// This extension is not supported by type CRL
	if(type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	if(isPresent())
	{
		std::string extendedKeyUsageString;

		if(isCritical()) extendedKeyUsageString += "critical,";

		StringList::const_iterator it = m_impl->usage.begin();
		for(; it != m_impl->usage.end(); ++it)
		{
			extendedKeyUsageString += (*it)+",";
		}

		ca.getConfig()->setValue(type2Section(type, true),
		                         "extendedKeyUsage",
		                         extendedKeyUsageString.erase(extendedKeyUsageString.length()-1));
	}
	else
	{
		ca.getConfig()->deleteValue(type2Section(type, true), "extendedKeyUsage");
	}
}

bool
ExtendedKeyUsageExt::valid() const
{
	if(!isPresent()) return true;

	if(m_impl->usage.empty())
	{
		return false;
	}

	StringList::const_iterator it = m_impl->usage.begin();
	for(;it != m_impl->usage.end(); it++)
	{
		if(!checkValue(*it))
		{
			return false;
		}
	}
	return true;
}

std::vector<std::string>
ExtendedKeyUsageExt::verify() const
{
	std::vector<std::string> result;

	if(!isPresent()) return result;

	if(m_impl->usage.empty())
	{
		result.push_back(std::string("invalid ExtendedKeyUsageExt."));
	}

	StringList::const_iterator it = m_impl->usage.begin();
	for(;it != m_impl->usage.end(); it++)
	{
		if(!checkValue(*it))
		{
			result.push_back(str::form("invalid additionalOID(%s)", (*it).c_str()));
		}
	}
	LOGIT_DEBUG_STRINGARRAY("ExtendedKeyUsageExt::verify()", result);
	return result;
}

std::vector<std::string>
ExtendedKeyUsageExt::dump() const
{
	std::vector<std::string> result;
	result.push_back("ExtendedKeyUsageExt::dump()");

	appendArray(result, ExtensionBase::dump());
	if(!isPresent()) return result;

	StringList::const_iterator it = m_impl->usage.begin();
	for(; it != m_impl->usage.end(); ++it)
	{
		result.push_back("Extended KeyUsage = " + (*it));
	}

	return result;
}

bool
ExtendedKeyUsageExt::checkValue(const std::string& value) const
{
	if(OBJ_sn2nid(value.c_str()) == NID_undef)
	{
		return initOIDCheck().isValid(value);
	}
	else
	{
		return true;
	}
}

}
