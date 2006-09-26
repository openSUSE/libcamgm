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

  File:       CRLDistributionPointsExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/CRLDistributionPointsExtension.hpp>
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

class CRLDistributionPointsExtImpl : public blocxx::COWIntrusiveCountableBase
{
	public:
	CRLDistributionPointsExtImpl()
		: altNameList(List<LiteralValue>())
	{}

	CRLDistributionPointsExtImpl(const CRLDistributionPointsExtImpl& impl)
		: COWIntrusiveCountableBase(impl)
		, altNameList(impl.altNameList)
	{}

	~CRLDistributionPointsExtImpl() {}

	CRLDistributionPointsExtImpl* clone() const
	{
		return new CRLDistributionPointsExtImpl(*this);
	}

	blocxx::List<LiteralValue> altNameList;
};

	
CRLDistributionPointsExt::CRLDistributionPointsExt()
	: ExtensionBase()
	, m_impl(new CRLDistributionPointsExtImpl())
{}

CRLDistributionPointsExt::CRLDistributionPointsExt(CAConfig* caConfig, Type type)
	: ExtensionBase()
	, m_impl(new CRLDistributionPointsExtImpl())
{
	// These types are not supported by this object
	if(type == E_CRL        || type == E_Client_Req ||
	   type == E_Server_Req || type == E_CA_Req      )
	{
		LOGIT_ERROR("wrong type" << type);
		BLOCXX_THROW(limal::ValueException,
		             Format(__("Wrong type: %1."), type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, true), "crlDistributionPoints");
	if(p)
	{
		StringArray   sp   = PerlRegEx("\\s*,\\s*")
			.split(caConfig->getValue(type2Section(type, true), "crlDistributionPoints"));
		if(sp[0].equalsIgnoreCase("critical"))  setCritical(true);

		StringArray::const_iterator it = sp.begin();
		for(; it != sp.end(); ++it)
		{
			if((*it).indexOf(":") != String::npos)
			{
				try
				{                    
					LiteralValue lv = LiteralValue(*it);
					m_impl->altNameList.push_back(lv);
				}
				catch(blocxx::Exception& e)
				{
					LOGIT_ERROR("invalid value: " << *it);
				}
			}
		}
	}
	setPresent(p);
}

CRLDistributionPointsExt::CRLDistributionPointsExt(const CRLDistributionPointsExt& extension)
	: ExtensionBase(extension)
	, m_impl(extension.m_impl)
{}

CRLDistributionPointsExt::~CRLDistributionPointsExt()
{}

CRLDistributionPointsExt&
CRLDistributionPointsExt::operator=(const CRLDistributionPointsExt& extension)
{
	if(this == &extension) return *this;
    
	ExtensionBase::operator=(extension);
	m_impl = extension.m_impl;

	return *this;
}

void
CRLDistributionPointsExt::setCRLDistributionPoints(blocxx::List<LiteralValue> dp)
{
	StringArray r = checkLiteralValueList(dp);
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(limal::ValueException, r[0].c_str());
	}
	m_impl->altNameList = dp;
	setPresent(true);
}

blocxx::List<LiteralValue>
CRLDistributionPointsExt::getCRLDistributionPoints() const
{
	if(!isPresent())
	{
		LOGIT_ERROR("CRLDistributionPointsExt is not present");
		BLOCXX_THROW(limal::RuntimeException,
		             __("CRLDistributionPointsExt is not present."));
	}
	return m_impl->altNameList;
}

void
CRLDistributionPointsExt::commit2Config(CA& ca, Type type) const
{
	if(!valid())
	{
		LOGIT_ERROR("invalid CRLDistributionPointsExt object");
		BLOCXX_THROW(limal::ValueException,
		             __("Invalid CRLDistributionPointsExt object."));
	}

	// These types are not supported by this object
	if(type == E_CRL        || type == E_Client_Req ||
	   type == E_Server_Req || type == E_CA_Req      )
	{
		LOGIT_ERROR("wrong type" << type);
		BLOCXX_THROW(limal::ValueException,
		             Format(__("Wrong type: %1."), type).c_str());
	}

	if(isPresent())
	{
		String extString;

		if(isCritical()) extString += "critical,";

		blocxx::List<LiteralValue>::const_iterator it = m_impl->altNameList.begin();
		for(;it != m_impl->altNameList.end(); ++it)
		{
			extString += (*it).toString()+",";
		}

		ca.getConfig()->setValue(type2Section(type, true), "crlDistributionPoints",
		                         extString.erase(extString.length()-1));
	}
	else
	{
		ca.getConfig()->deleteValue(type2Section(type, true), "crlDistributionPoints");
	}
}

bool
CRLDistributionPointsExt::valid() const
{
	if(!isPresent())
	{
		LOGIT_DEBUG("return CRLDistributionPointsExt::valid() is true");
		return true;
	}

	if(m_impl->altNameList.empty()) return false;

	StringArray r = checkLiteralValueList(m_impl->altNameList);
	if(!r.empty())
	{
		LOGIT_DEBUG(r[0]);
		return false;
	}
	return true;
}

blocxx::StringArray
CRLDistributionPointsExt::verify() const
{
	blocxx::StringArray result;
    
	if(!isPresent()) return result;
    
	if(m_impl->altNameList.empty())
	{
		result.append(String("No value for CRLDistributionPointsExt."));
	}
	result.appendArray(checkLiteralValueList(m_impl->altNameList));
    
	LOGIT_DEBUG_STRINGARRAY("CRLDistributionPointsExt::verify()", result);
	return result;
}

blocxx::StringArray
CRLDistributionPointsExt::dump() const
{
	StringArray result;
	result.append("CRLDistributionPointsExt::dump()");

	result.appendArray(ExtensionBase::dump());
	if(!isPresent()) return result;

	blocxx::List< LiteralValue >::const_iterator it = m_impl->altNameList.begin();
	for(; it != m_impl->altNameList.end(); ++it)
	{
		result.appendArray((*it).dump());
	}
    
	return result;
}

}
}
