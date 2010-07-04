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
#include  <map>
#include  <blocxx/COWIntrusiveCountableBase.hpp>

#include  "DNObjectImpl.hpp"
#include  "DNObject_Priv.hpp"
#include  "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;
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
RDNObject::setRDNValue(const std::string& value)
{
	m_impl->value = value;
}


std::string
RDNObject::getType() const
{
	return m_impl->type;
}

std::string
RDNObject::getValue() const
{
	return m_impl->value;
}

std::string
RDNObject::getOpenSSLValue() const
{
	if(m_impl->value.empty()) return std::string();

	std::map<std::string, std::string> opensslKeys;
	opensslKeys["countryName"] = "C";
	opensslKeys["stateOrProvinceName"] = "ST";
	opensslKeys["localityName"] = "L";
	opensslKeys["organizationName"] = "O";
	opensslKeys["organizationalUnitName"] = "OU";
	opensslKeys["commonName"] = "CN";
	opensslKeys["emailAddress"] = "emailAddress";
	//opensslKeys[""] = "";

	std::string ret;
	std::map<std::string, std::string>::const_iterator it = opensslKeys.find(m_impl->type);

	if( it != opensslKeys.end())
	{
		ret += (*it).second + "=";
	}
	else
	{
		LOGIT_ERROR("Invalid type:" << m_impl->type);
		BLOCXX_THROW(ca_mgm::ValueException,
		             // %s is the invalid string for a DN type
		             str::form(__("Invalid type %s."), m_impl->type.c_str()).c_str());
	}

    //PosixRegEx regex("([\\\\/])");
	//std::string v = regex.replace(m_impl->value, "\\1", true);
    std::string v = str::escape(m_impl->value, '\\');
    v = str::escape(v, '/');
    //LOGIT_DEBUG("RDNObject::getOpenSSLValue Value: '" << m_impl->value << "'  quoted: '" << v << "'");

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
    // was UTF8Length
	if(m_impl->min != 0 && m_impl->value.size() < m_impl->min)
	{
		LOGIT_DEBUG("value(" << m_impl->value <<
		            ") is too small. Value has to be a minimal length of " <<
		            m_impl->min);
		return false;
	}
    // was UTF8Length
	if(m_impl->max != 0 && m_impl->value.size() > m_impl->max)
	{
		LOGIT_DEBUG("value(" << m_impl->value <<
		            ") is too long. Value has to be a maximal length of " <<
		            m_impl->max);
		return false;
	}

	return true;
}

std::vector<std::string>
RDNObject::verify() const
{
	std::vector<std::string> result;

	if(m_impl->type.empty())
	{
		result.push_back("type is empty");
	}

    // was UTF8Length
	if(m_impl->min != 0 && m_impl->value.size() < m_impl->min)
	{
		result.push_back("Value(" + m_impl->value +
		              ") is too small. Value has to be a minimal length of " +
		              str::numstring(m_impl->min));
	}

    // was UTF8Length
	if(m_impl->max != 0 && m_impl->value.size() > m_impl->max)
	{
		result.push_back("Value(" + m_impl->value +
		              ") is too long. Value has to be a maximal length of " +
		              str::numstring(m_impl->max));
	}

	LOGIT_DEBUG_STRINGARRAY("RDNObject::verify()", result);

	return result;
}

std::vector<std::string>
RDNObject::dump() const
{
	std::vector<std::string> result;
	result.push_back("RDNObject::dump()");

	result.push_back(m_impl->type + "=" + m_impl->value);
	result.push_back("Prompt:" + m_impl->prompt);
	result.push_back("Min:" + str::numstring(m_impl->min));
	result.push_back("Max:" + str::numstring(m_impl->max));
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
		BLOCXX_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %d."), type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, false), "distinguished_name");
	if(!p)
	{
		LOGIT_ERROR("missing section 'distinguished_name' in config file");
		BLOCXX_THROW(ca_mgm::SyntaxException,
		             __("Missing section 'distinguished_name' in the configuration file."));
	}
	std::string dnSect = caConfig->getValue(type2Section(type, false),
	                                   "distinguished_name");

	StringList dnKeys = caConfig->getKeylist(dnSect);

	if(dnKeys.empty())
	{
		LOGIT_ERROR("Can not parse Section " << dnSect);
		BLOCXX_THROW(ca_mgm::SyntaxException,
		             str::form(__("Cannot parse section %s."), dnSect.c_str()).c_str());
	}
	StringList::const_iterator it = dnKeys.begin();

	std::string fieldName;
	std::string prompt;
	std::string defaultValue;
	std::string min("0");
	std::string max("0");

	for(; it != dnKeys.end(); ++it)
	{
		if(str::endsWithCI(*it, "_default"))
		{
			if(str::startsWithCI(*it, fieldName))
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
		else if(str::endsWithCI(*it,  "_min"))
		{
			if(str::startsWithCI(*it, fieldName))
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
		else if(str::endsWithCI(*it, "_max"))
		{
			if(str::startsWithCI(*it, fieldName))
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
				                                    str::strtonum<uint32_t>(min),
				                                    str::strtonum<uint32_t>(max)));
			}

			// reset
			prompt       = std::string();
			defaultValue = std::string();
			min          = std::string("0");
			max          = std::string("0");

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
		                                    str::strtonum<uint32_t>(min),
		                                    str::strtonum<uint32_t>(max)));
	}
}

DNObject::DNObject(const std::list<RDNObject> &dn)
	: m_impl(new DNObjectImpl())
{
	m_impl->dn = dn;
	std::vector<std::string> r = this->verify();
	if(!r.empty())
	{
		BLOCXX_THROW(ca_mgm::ValueException, r[0].c_str());
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
DNObject::setDN(const std::list<RDNObject> &dn)
{
	std::vector<std::string> r = checkRDNList(dn);
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(ca_mgm::ValueException, r[0].c_str());
	}
	m_impl->dn = dn;
}

std::list<RDNObject>
DNObject::getDN() const
{
	return m_impl->dn;
}

std::string
DNObject::getOpenSSLString() const
{
	std::string ret;

	std::list<RDNObject>::const_iterator it = m_impl->dn.begin();
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
	std::vector<std::string> r = checkRDNList(m_impl->dn);
	if(!r.empty())
	{
		LOGIT_DEBUG(r[0]);
		return false;
	}
	return true;
}

std::vector<std::string>
DNObject::verify() const
{
	std::vector<std::string> result;

	if(m_impl->dn.empty())
	{
		result.push_back("empty DN");
	}
	appendArray(result, checkRDNList(m_impl->dn));

	LOGIT_DEBUG_STRINGARRAY("DNObject::verify()", result);

	return result;
}

std::vector<std::string>
DNObject::checkRDNList(const std::list<RDNObject>& list) const
{
	std::vector<std::string> result;

	std::list<RDNObject>::const_iterator it = list.begin();
	for(; it != list.end(); ++it)
	{
		appendArray(result, (*it).verify());
	}
	return result;
}

std::vector<std::string>
DNObject::dump() const
{
	std::vector<std::string> result;
	result.push_back("DNObject::dump()");

	std::list< RDNObject >::const_iterator it = m_impl->dn.begin();
	for(; it != m_impl->dn.end(); ++it)
	{
		appendArray(result, (*it).dump());
	}

	return result;
}

}
