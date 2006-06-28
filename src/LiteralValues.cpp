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

  File:       LiteralValues.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/LiteralValues.hpp>
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


class LiteralValueImpl : public blocxx::COWIntrusiveCountableBase
{
	public:
	String literalType;
	String literalValue;
	
	LiteralValueImpl()
		: literalType(String()), literalValue(String())
	{}

	LiteralValueImpl(const String& type,
	                 const String& value)
		: literalType(type), literalValue(value)
	{}

	LiteralValueImpl(const LiteralValueImpl &lv)
		: blocxx::COWIntrusiveCountableBase(lv),
		  literalType(lv.literalType),
		  literalValue(lv.literalValue)
	{}

	virtual ~LiteralValueImpl() {}

	LiteralValueImpl* clone() const
	{
		return new LiteralValueImpl(*this);
	}
};

	
LiteralValue::LiteralValue() 
	: m_impl(new LiteralValueImpl())
{}

LiteralValue::LiteralValue(const String &type, const String &value) 
    : m_impl(new LiteralValueImpl(type, value))
{
	StringArray r = this->verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(limal::ValueException, r[0].c_str());
	}
}

LiteralValue::LiteralValue(const String& value)
	: m_impl(new LiteralValueImpl())
{
	StringArray   sp   = PerlRegEx("^(\\w+):(.*)$").capture(value);
    
	if(sp[1].equalsIgnoreCase("email"))
	{
		m_impl->literalType  = sp[1];
		m_impl->literalValue = sp[2];
	}
	else if(sp[1].equalsIgnoreCase("URI"))
	{
		m_impl->literalType  = sp[1];
		m_impl->literalValue = sp[2];
	}
	else if(sp[1].equalsIgnoreCase("DNS"))
	{
		m_impl->literalType  = sp[1];
		m_impl->literalValue = sp[2];
	}
	else if(sp[1].equalsIgnoreCase("RID"))
	{
		m_impl->literalType  = sp[1];
		m_impl->literalValue = sp[2];
	}
	else if(sp[1].equalsIgnoreCase("IP"))
	{
		m_impl->literalType  = sp[1];
		m_impl->literalValue = sp[2];
	}
	else
	{
		LOGIT_DEBUG("unknown type: "<< sp[1] << " = " << sp[2]);
		BLOCXX_THROW(limal::ValueException,
		             __("Unknown type"));
	}
}

LiteralValue::LiteralValue(const LiteralValue& value)
	: m_impl(value.m_impl)
{}


LiteralValue&
LiteralValue::operator=(const LiteralValue& value)
{
    if(this == &value) return *this;

    m_impl = value.m_impl;
    
    return *this;
}

LiteralValue::~LiteralValue()
{}
        

void
LiteralValue::setLiteral(const String &type, const String &value)
{
	String dType = m_impl->literalType;
	String dValue = m_impl->literalValue;
	
	m_impl->literalType = type;
	m_impl->literalValue = value;
	
	StringArray r = this->verify();
	if(!r.empty())
	{
		m_impl->literalType = dType;
		m_impl->literalValue = dValue;
		
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(limal::ValueException, r[0].c_str());
	}
}

void
LiteralValue::setValue(const String &value) 
{
	String dValue = m_impl->literalValue;
    
	m_impl->literalValue = value; 

	StringArray r = this->verify();
	if(!r.empty())
	{
		m_impl->literalValue = dValue;
		
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(limal::ValueException, r[0].c_str());
	}
}

blocxx::String
LiteralValue::getValue() const 
{
	return m_impl->literalValue; 
}

blocxx::String
LiteralValue::getType() const
{
	return m_impl->literalType;
}

bool
LiteralValue::valid() const
{
	if(m_impl->literalType == "email")
	{
		ValueCheck check = initEmailCheck();
		if(!check.isValid(m_impl->literalValue))
		{
			LOGIT_DEBUG("Wrong LiteralValue for type 'email': " << m_impl->literalValue);
			return false;
		}
	}
	else if(m_impl->literalType == "URI")
	{
		ValueCheck check = initURICheck();
		if(!check.isValid(m_impl->literalValue))
		{
			LOGIT_DEBUG("Wrong LiteralValue for type 'URI': " << m_impl->literalValue);
			return false;
		}
	}
	else if(m_impl->literalType == "DNS")
	{
		ValueCheck check = initDNSCheck();
		if(!check.isValid(m_impl->literalValue))
		{
			LOGIT_DEBUG("Wrong LiteralValue for type 'DNS': " << m_impl->literalValue);
			return false;
		}
	}
	else if(m_impl->literalType == "RID")
	{
		ValueCheck check = initOIDCheck();
		if(!check.isValid(m_impl->literalValue))
		{
			LOGIT_DEBUG("Wrong LiteralValue for type 'RID': " << m_impl->literalValue);
			return false;
		}
	}
	else if(m_impl->literalType == "IP")
	{
		ValueCheck check = initIPCheck();
		if(!check.isValid(m_impl->literalValue))
		{
			LOGIT_DEBUG("Wrong LiteralValue for type 'IP': " << m_impl->literalValue);
			return false;
		}
	}
	else
	{
		LOGIT_DEBUG("Unknown Type in LiteralValue: " << m_impl->literalType);
		return false;
	}
	return true;
}

blocxx::StringArray
LiteralValue::verify() const
{
	StringArray result;

	if(m_impl->literalType == "email")
	{
		ValueCheck check = initEmailCheck();
		if(!check.isValid(m_impl->literalValue))
		{
			LOGIT_DEBUG("Wrong LiteralValue for type 'email': " << m_impl->literalValue);
			result.append(Format("Wrong LiteralValue for type 'email': %1",
			                     m_impl->literalValue).toString());
		}
	}
	else if(m_impl->literalType == "URI")
	{
		ValueCheck check = initURICheck();
		if(!check.isValid(m_impl->literalValue))
		{
			LOGIT_DEBUG("Wrong LiteralValue for type 'URI': " << m_impl->literalValue);
			result.append(Format("Wrong LiteralValue for type 'URI': %1",
			                     m_impl->literalValue).toString());
		}
	}
	else if(m_impl->literalType == "DNS")
	{
		ValueCheck check = initDNSCheck();
		if(!check.isValid(m_impl->literalValue))
		{
			LOGIT_DEBUG("Wrong LiteralValue for type 'DNS': " << m_impl->literalValue);
			result.append(Format("Wrong LiteralValue for type 'DNS': %1",
			                     m_impl->literalValue).toString());
		}
	}
	else if(m_impl->literalType == "RID")
	{
		ValueCheck check = initOIDCheck();
		if(!check.isValid(m_impl->literalValue))
		{
			LOGIT_DEBUG("Wrong LiteralValue for type 'RID': " << m_impl->literalValue);
			result.append(Format("Wrong LiteralValue for type 'RID': %1",
			                     m_impl->literalValue).toString());
		}
	}
	else if(m_impl->literalType == "IP")
	{
		ValueCheck check = initIPCheck();
		if(!check.isValid(m_impl->literalValue))
		{
			LOGIT_DEBUG("Wrong LiteralValue for type 'IP': " << m_impl->literalValue);
			result.append(Format("Wrong LiteralValue for type 'IP': %1",
			                     m_impl->literalValue).toString());
		}
	}
	else
	{
		LOGIT_DEBUG("Unknown Type in LiteralValue: " << m_impl->literalType);
		result.append(Format("Unknown Type in LiteralValue: %1",
		                     m_impl->literalType).toString());
	}
	return result;
}

blocxx::String
LiteralValue::toString() const
{
	return (m_impl->literalType + ":" + m_impl->literalValue);
}

blocxx::StringArray
LiteralValue::dump() const
{
	StringArray result;
	result.append("LiteralValue::dump()");
	
	result.append(m_impl->literalType + ":" + m_impl->literalValue);
	
	return result;
}

// ------------------------------------------
// friends
// ------------------------------------------

bool
operator==(const LiteralValue &l, const LiteralValue &r)
{
	if(l.getType() == r.getType() &&
	   l.getValue() == r.getValue())
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool
operator<(const LiteralValue &l, const LiteralValue &r)
{
	if(l.getType() < r.getType() ||
	   l.getValue() < r.getValue())
	{
		return true;
	}
	else
	{
		return false;
	}
}

}
}
