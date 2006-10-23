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
#include  <blocxx/Format.hpp>
#include  <blocxx/COWIntrusiveCountableBase.hpp>

#include "Utils.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;

class ExtendedKeyUsageExtImpl : public blocxx::COWIntrusiveCountableBase
{
	public:
	ExtendedKeyUsageExtImpl()
		: usage(StringList())
	{}

	ExtendedKeyUsageExtImpl(const ExtendedKeyUsageExtImpl& impl)
		: COWIntrusiveCountableBase(impl)
		, usage(impl.usage)
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
		BLOCXX_THROW(limal::ValueException,
		             Format(__("Wrong type: %1."), type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, true), "extendedKeyUsage");
	if(p)
	{
		String      ct    = caConfig->getValue(type2Section(type, true),
		                                       "extendedKeyUsage");
		StringArray sp    = PerlRegEx("\\s*,\\s*").split(ct);
    	
		StringArray::const_iterator it = sp.begin();
		if(sp[0].equalsIgnoreCase("critical"))
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
			BLOCXX_THROW(limal::ValueException,
			             Format(__("Invalid ExtendedKeyUsage option %1."),
			                    *it).c_str());
		}
	}
    
	if(m_impl->usage.empty())
	{
		BLOCXX_THROW(limal::ValueException,
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
			BLOCXX_THROW(limal::ValueException,
			             Format(__("Invalid ExtendedKeyUsage option %1."),
			                    *it).c_str());
		}
	}

	if(m_impl->usage.empty())
	{
		BLOCXX_THROW(limal::ValueException,
		             __("Invalid ExtendedKeyUsageExt."));
	}

	setPresent(true);
}


StringList
ExtendedKeyUsageExt::getExtendedKeyUsage() const
{
	if(!isPresent())
	{
		BLOCXX_THROW(limal::RuntimeException,
		             __("ExtendedKeyUsageExt is not present."));
	}
	return m_impl->usage;
}
        
bool
ExtendedKeyUsageExt::isEnabledFor(const String& extKeyUsage) const
{
	// if ! isPresent() ... throw exceptions?
	if(!isPresent() || m_impl->usage.empty()) return false;

	StringList::const_iterator it = m_impl->usage.begin();
	for(;it != m_impl->usage.end(); ++it)
	{
		if(extKeyUsage.equalsIgnoreCase(*it))
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
		BLOCXX_THROW(limal::ValueException,
		             __("Invalid ExtendedKeyUsageExt object."));
	}

	// This extension is not supported by type CRL
	if(type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		BLOCXX_THROW(limal::ValueException,
		             Format(__("Wrong type: %1."), type).c_str());
	}

	if(isPresent())
	{
		String extendedKeyUsageString;

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

blocxx::StringArray
ExtendedKeyUsageExt::verify() const
{
	blocxx::StringArray result;

	if(!isPresent()) return result;

	if(m_impl->usage.empty())
	{
		result.append(String("invalid ExtendedKeyUsageExt."));
	}

	StringList::const_iterator it = m_impl->usage.begin();
	for(;it != m_impl->usage.end(); it++)
	{
		if(!checkValue(*it))
		{
			result.append(Format("invalid additionalOID(%1)", *it).toString());
		}
	}
	LOGIT_DEBUG_STRINGARRAY("ExtendedKeyUsageExt::verify()", result);
	return result;
}

blocxx::StringArray
ExtendedKeyUsageExt::dump() const
{
	StringArray result;
	result.append("ExtendedKeyUsageExt::dump()");

	result.appendArray(ExtensionBase::dump());
	if(!isPresent()) return result;

	StringList::const_iterator it = m_impl->usage.begin();
	for(; it != m_impl->usage.end(); ++it)
	{
		result.append("Extended KeyUsage = " + (*it));
	}

	return result;
}

bool
ExtendedKeyUsageExt::checkValue(const String& value) const
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
}
