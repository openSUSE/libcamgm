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

  File:       DNObject.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/DNObject.hpp>
#include  <limal/ca-mgm/CAConfig.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>
#include  <blocxx/Map.hpp>
#include  <blocxx/COWIntrusiveCountableBase.hpp>

#include  "DNObjectImpl.hpp"
#include  "DNObject_Priv.hpp"
#include  "Utils.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;
	
	
RDNObject::RDNObject()
	: m_impl(new RDNObjectImpl())
{}
	
RDNObject::RDNObject(const RDNObject& rdn)
	: m_impl(rdn.m_impl)
{}

RDNObject::~RDNObject()
{}

RDNObject&
RDNObject::operator=(const RDNObject& rdn)
{
	if(this == &rdn) return *this;
    
	m_impl = rdn.m_impl;

	return *this;
}

void
RDNObject::setRDNValue(const String& value)
{
	m_impl->value = value;
}


blocxx::String
RDNObject::getType() const
{
	return m_impl->type;
}

blocxx::String
RDNObject::getValue() const
{
	return m_impl->value;
}

blocxx::String
RDNObject::getOpenSSLValue() const
{
	if(m_impl->value.empty()) return String();

	Map<String, String> opensslKeys;
	opensslKeys["countryName"] = "C";
	opensslKeys["stateOrProvinceName"] = "ST";
	opensslKeys["localityName"] = "L";
	opensslKeys["organizationName"] = "O";
	opensslKeys["organizationalUnitName"] = "OU";
	opensslKeys["commonName"] = "CN";
	opensslKeys["emailAddress"] = "emailAddress";
	//opensslKeys[""] = "";

	String ret;
	Map<String, String>::const_iterator it = opensslKeys.find(m_impl->type);

	if( it != opensslKeys.end())
	{        
		ret += (*it).second + "=";
	}
	else
	{
		LOGIT_ERROR("Invalid type:" << m_impl->type);
		BLOCXX_THROW(limal::ValueException, Format("Invalid type:%1", m_impl->type).c_str());
	}

	PerlRegEx regex("([\\\\/])");
	String v = regex.replace(m_impl->value, "\\\\\\1", true);

	ret += v;

	return ret;
}

bool
RDNObject::valid() const
{
	if(m_impl->type.empty())
	{
		LOGIT_DEBUG("type is empty");
		return false;
	}

	if(m_impl->min != 0 && m_impl->value.UTF8Length() < m_impl->min)
	{
		LOGIT_DEBUG("value(" << m_impl->value <<
		            ") is too small. Value has to be a minimal length of " <<
		            m_impl->min);
		return false;
	}

	if(m_impl->max != 0 && m_impl->value.UTF8Length() > m_impl->max)
	{
		LOGIT_DEBUG("value(" << m_impl->value <<
		            ") is too long. Value has to be a maximal length of " <<
		            m_impl->max);
		return false;
	}

	return true;
}

blocxx::StringArray
RDNObject::verify() const
{
	StringArray result;

	if(m_impl->type.empty())
	{
		result.append("type is empty");
	}

	if(m_impl->min != 0 && m_impl->value.UTF8Length() < m_impl->min)
	{
		result.append("Value(" + m_impl->value + 
		              ") is too small. Value has to be a minimal length of " +
		              String(m_impl->min));
	}

	if(m_impl->max != 0 && m_impl->value.UTF8Length() > m_impl->max)
	{
		result.append("Value(" + m_impl->value + 
		              ") is too long. Value has to be a maximal length of " +
		              String(m_impl->max));
	}

	LOGIT_DEBUG_STRINGARRAY("RDNObject::verify()", result);

	return result;
}

blocxx::StringArray
RDNObject::dump() const
{
	StringArray result;
	result.append("RDNObject::dump()");

	result.append(m_impl->type + "=" + m_impl->value);
	result.append("Prompt:" + m_impl->prompt);
	result.append("Min:" + String(m_impl->min));
	result.append("Max:" + String(m_impl->max));
	return result;
}

bool
operator==(const RDNObject &l, const RDNObject &r)
{
	if(l.getType()  == r.getType() &&
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
operator<(const RDNObject &l, const RDNObject &r)
{
	if(l.getType()  < r.getType())
	{
		return true;
	}
	else if(l.getType()  == r.getType())
	{
		if(l.getValue() < r.getValue())
		{
			return true;
		}
		else
		{
			return false;
		}
	} else{
		return false;
	}
}


// ######################################################################

DNObject::DNObject()
	: m_impl(new DNObjectImpl())
{
	m_impl->dn.push_back(RDNObject_Priv("countryName", ""));
	m_impl->dn.push_back(RDNObject_Priv("stateOrProvinceName", ""));
	m_impl->dn.push_back(RDNObject_Priv("localityName", ""));
	m_impl->dn.push_back(RDNObject_Priv("organizationName", ""));
	m_impl->dn.push_back(RDNObject_Priv("organizationalUnitName", ""));
	m_impl->dn.push_back(RDNObject_Priv("commonName", ""));
	m_impl->dn.push_back(RDNObject_Priv("emailAddress", ""));
}

DNObject::DNObject(CAConfig* caConfig, Type type)
	: m_impl(new DNObjectImpl())
{
	if(type == E_Client_Cert || type == E_Server_Cert ||
	   type == E_CA_Cert     || type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, false), "distinguished_name");
	if(!p)
	{
		LOGIT_ERROR("missing section 'distinguished_name' in config file");
		BLOCXX_THROW(limal::SyntaxException, 
		             "missing section 'distinguished_name' in config file");
	}
	String dnSect = caConfig->getValue(type2Section(type, false), 
	                                   "distinguished_name");

	StringList dnKeys = caConfig->getKeylist(dnSect);

	if(dnKeys.empty())
	{
		LOGIT_ERROR("Can not parse Section " << dnSect);
		BLOCXX_THROW(limal::SyntaxException, 
		             Format("Can not parse Section %1", dnSect).c_str());
	}
	StringList::const_iterator it = dnKeys.begin();

	String fieldName;
	String prompt;
	String defaultValue;
	String min("0");
	String max("0");

	for(; it != dnKeys.end(); ++it)
	{
		if((*it).endsWith("_default", String::E_CASE_INSENSITIVE))
		{
			if((*it).startsWith(fieldName, String::E_CASE_INSENSITIVE))
			{                
				defaultValue = caConfig->getValue(dnSect, *it);
			}
			else
			{
				LOGIT_INFO("Wrong order of section '" << dnSect <<
				           "'. FieldName is '" << fieldName <<
				           "' but parsed Key is '" << *it << 
				           "'. Ignoring value.");
				continue;
			}
		}
		else if((*it).endsWith("_min", String::E_CASE_INSENSITIVE))
		{
			if((*it).startsWith(fieldName, String::E_CASE_INSENSITIVE))
			{
				min = caConfig->getValue(dnSect, *it);
			}
			else
			{
				LOGIT_INFO("Wrong order of section '" << dnSect <<
				           "'. FieldName is '" << fieldName <<
				           "' but parsed Key is '" << *it << 
				           "'. Ignoring value.");
				continue;
			}
		}
		else if((*it).endsWith("_max", String::E_CASE_INSENSITIVE))
		{
			if((*it).startsWith(fieldName, String::E_CASE_INSENSITIVE))
			{
				max = caConfig->getValue(dnSect, *it);
			}
			else
			{
				LOGIT_INFO("Wrong order of section '" << dnSect <<
				           "'. FieldName is '" << fieldName <<
				           "' but parsed Key is '" << *it << 
				           "'. Ignoring value.");
				continue;
			}
		}
		else
		{
			// A new fieldName
			//
			// commit values
			if(!fieldName.empty()) {

				m_impl->dn.push_back(RDNObject_Priv(fieldName,
				                                    defaultValue,
				                                    prompt,
				                                    min.toUInt32(),
				                                    max.toUInt32()));
			}

			// reset
			prompt       = String();
			defaultValue = String();
			min          = String("0");
			max          = String("0");

			fieldName    = *it;
			prompt       = caConfig->getValue(dnSect, *it);
		}
	}
	// commit the last values
	if(!fieldName.empty())
	{        
		m_impl->dn.push_back(RDNObject_Priv(fieldName,
		                                    defaultValue,
		                                    prompt,
		                                    min.toUInt32(),
		                                    max.toUInt32()));
	}
}

DNObject::DNObject(const blocxx::List<RDNObject> &dn)
	: m_impl(new DNObjectImpl())
{
	m_impl->dn = dn;
	StringArray r = this->verify();
	if(!r.empty())
	{
		BLOCXX_THROW(limal::ValueException, r[0].c_str());
	}
}

DNObject::DNObject(const DNObject& dn)
	: m_impl(dn.m_impl)
{}

DNObject::~DNObject()
{}

DNObject&
DNObject::operator=(const DNObject& dn)
{
	if(this == &dn) return *this;
    
	m_impl = dn.m_impl;
    
	return *this;
}

void
DNObject::setDN(const blocxx::List<RDNObject> &dn)
{
	StringArray r = checkRDNList(dn);
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(limal::ValueException, r[0].c_str());
	}
	m_impl->dn = dn;
}

blocxx::List<RDNObject>
DNObject::getDN() const
{
	return m_impl->dn;
}

blocxx::String
DNObject::getOpenSSLString() const
{
	String ret;

	blocxx::List<RDNObject>::const_iterator it = m_impl->dn.begin();
	for(; it != m_impl->dn.end(); ++it)
	{
		if(! (*it).getOpenSSLValue().empty())
		{            
			ret += "/" + (*it).getOpenSSLValue();
		}
	}
    
	return ret;
}

bool
DNObject::valid() const
{
	if(m_impl->dn.empty())
	{
		LOGIT_DEBUG("empty DN");
		return false;
	}
	StringArray r = checkRDNList(m_impl->dn);
	if(!r.empty())
	{
		LOGIT_DEBUG(r[0]);
		return false;
	}
	return true;
}

blocxx::StringArray
DNObject::verify() const
{
	StringArray result;

	if(m_impl->dn.empty())
	{
		result.append("empty DN");
	}
	result.appendArray(checkRDNList(m_impl->dn));
    
	LOGIT_DEBUG_STRINGARRAY("DNObject::verify()", result);
    
	return result;
}

blocxx::StringArray
DNObject::checkRDNList(const blocxx::List<RDNObject>& list) const
{
	StringArray result;
    
	blocxx::List<RDNObject>::const_iterator it = list.begin();
	for(; it != list.end(); ++it)
	{
		result.appendArray((*it).verify());
	}
	return result;
}

blocxx::StringArray
DNObject::dump() const
{
	StringArray result;
	result.append("DNObject::dump()");

	blocxx::List< RDNObject >::const_iterator it = m_impl->dn.begin();
	for(; it != m_impl->dn.end(); ++it)
	{
		result.appendArray((*it).dump());
	}
    
	return result;
}

}
}
