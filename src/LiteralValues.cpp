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
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <limal/String.hpp>


#include  "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;


class LiteralValueImpl
{
public:
	std::string literalType;
	std::string literalValue;

	LiteralValueImpl()
		: literalType(std::string()), literalValue(std::string())
	{}

	LiteralValueImpl(const std::string& type,
	                 const std::string& value)
		: literalType(type), literalValue(value)
	{}

	LiteralValueImpl(const LiteralValueImpl &lv)
		: literalType(lv.literalType)
		, literalValue(lv.literalValue)
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

LiteralValue::LiteralValue(const std::string &type, const std::string &value)
	: m_impl(new LiteralValueImpl(type, value))
{
	std::vector<std::string> r = this->verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		CA_MGM_THROW(ca_mgm::ValueException, r[0].c_str());
	}
}

LiteralValue::LiteralValue(const std::string& value)
	: m_impl(new LiteralValueImpl())
{
	std::vector<std::string>   sp   = PerlRegEx("^([\\w\\d.]+):(.*)$").capture(value);

	if(str::compareCI(sp[1], "email") == 0)
	{
		m_impl->literalType  = sp[1];
		m_impl->literalValue = sp[2];
	}
	else if(str::compareCI(sp[1], "URI") == 0)
	{
		m_impl->literalType  = sp[1];
		m_impl->literalValue = sp[2];
	}
	else if(str::compareCI(sp[1], "DNS") == 0)
	{
		m_impl->literalType  = sp[1];
		m_impl->literalValue = sp[2];
	}
	else if(str::compareCI(sp[1], "RID") == 0)
	{
		m_impl->literalType  = sp[1];
		m_impl->literalValue = sp[2];
	}
	else if(str::compareCI(sp[1], "IP") == 0)
	{
		m_impl->literalType  = sp[1];
		m_impl->literalValue = sp[2];
	}
	else if(sp[1] == "1.3.6.1.4.1.311.20.2.3") // ms_upn
	{
		m_impl->literalType  = sp[1];
		m_impl->literalValue = sp[2];
	}
	else if(sp[1] == "1.3.6.1.5.2.2") // KRB5PrincipalName
	{
		m_impl->literalType  = sp[1];
		m_impl->literalValue = sp[2];
	}
	else
	{
		LOGIT_DEBUG("unknown type: "<< sp[1] << " = " << sp[2]);
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Unknown type."));
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
LiteralValue::setLiteral(const std::string &type, const std::string &value)
{
	std::string dType = m_impl->literalType;
	std::string dValue = m_impl->literalValue;

	m_impl->literalType = type;
	m_impl->literalValue = value;

	std::vector<std::string> r = this->verify();
	if(!r.empty())
	{
		m_impl->literalType = dType;
		m_impl->literalValue = dValue;

		LOGIT_ERROR(r[0]);
		CA_MGM_THROW(ca_mgm::ValueException, r[0].c_str());
	}
}

void
LiteralValue::setValue(const std::string &value)
{
	std::string dValue = m_impl->literalValue;

	m_impl->literalValue = value;

	std::vector<std::string> r = this->verify();
	if(!r.empty())
	{
		m_impl->literalValue = dValue;

		LOGIT_ERROR(r[0]);
		CA_MGM_THROW(ca_mgm::ValueException, r[0].c_str());
	}
}

std::string
LiteralValue::getValue() const
{
	return m_impl->literalValue;
}

std::string
LiteralValue::getType() const
{
	return m_impl->literalType;
}

std::string
LiteralValue::commit2Config(CA &ca, Type, uint32_t num) const
{

	if(m_impl->literalType == "email" ||
	   m_impl->literalType == "URI" ||
	   m_impl->literalType == "DNS" ||
	   m_impl->literalType == "RID" ||
	   m_impl->literalType == "IP")
	{
		return toString();
	}

	// Maybe add support for KRB5PrincipalName here
	/*
	  Using OpenSSL to create certificate with krb5PrincipalName
	  ----------------------------------------------------------

	  To make OpenSSL create certificate with krb5PrincipalName use
	  `openssl.cnf' as described below. To see an complete example of
	  creating client and KDC certificates, see the test-data generation
	  script `lib/hx509/data/gen-req.sh' in the source-tree. The certicates
	  it creates are used to test the PK-INIT functionality in
	  `tests/kdc/check-kdc.in'.

	  To use this example you have to use OpenSSL 0.9.8a or later.


	  [user_certificate]
	  subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:princ_name

	  [princ_name]
	  realm = EXP:0, GeneralString:MY.REALM
	  principal_name = EXP:1, SEQUENCE:principal_seq

	  [principal_seq]
	  name_type = EXP:0, INTEGER:1
	  name_string = EXP:1, SEQUENCE:principals

	  [principals]
	  princ1 = GeneralString:userid
	*/

	if(m_impl->literalType == "1.3.6.1.4.1.311.20.2.3")  // ms_upn
	{
		return "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:" + m_impl->literalValue;
	}
	else if(m_impl->literalType == "1.3.6.1.5.2.2")  // KRB5PrincipalName
	{
		std::string primary = "";
		std::string instance;
		std::string realm = "";

		std::vector<std::string> sa;
        str::split( getValue(), std::back_inserter(sa) ,"@/");
		std::string sectname1 = getValue()+str::numstring(num);

		if(sa.size() == 2) // primary@REALM
		{
			primary = sa[0];
			realm   = sa[1];
		}
		else if(sa.size() == 3)  // primary/instance@REALM
		{
			primary  = sa[0];
			instance = sa[1];
			realm    = sa[2];
		}
		else
		{
			// FIXME: or better throw an error?
			return "";
		}
		std::string sectname2 = primary+instance+str::numstring(num);
		std::string sectname3 = "basic"+primary+instance+str::numstring(num);

		std::string ret = "otherName:1.3.6.1.5.2.2;SEQUENCE:"+sectname1;

		ca.getConfig()->setValue(sectname1, "realm", "EXPLICIT:0, GeneralString:"+realm);
		ca.getConfig()->setValue(sectname1, "kerberosname", "EXPLICIT:1, SEQUENCE:"+sectname2);
		ca.getConfig()->setValue(sectname2, "nametype", "EXPLICIT:0, INTEGER:1");
		ca.getConfig()->setValue(sectname2, "namelist", "EXPLICIT:1, SEQUENCE:"+sectname3);

		ca.getConfig()->setValue(sectname3, "0.part", "GeneralString:"+primary);
		if(!instance.empty()) //we have an instance
		{
			ca.getConfig()->setValue(sectname3, "1.part", "GeneralString:"+instance);
		}
		return ret;
	}

	return "";
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
		ValueCheck check = initIP4Check();
		if(!check.isValid(m_impl->literalValue))
		{
			// IPv6 address is allowed too
			check = initIP6Check();
			if(!check.isValid(m_impl->literalValue))
			{
				LOGIT_DEBUG("Wrong LiteralValue for type 'IP': " << m_impl->literalValue);
				return false;
			}
		}
	}
	else if(m_impl->literalType == "1.3.6.1.4.1.311.20.2.3")  // ms_upn
	{
		ValueCheck check = initEmailCheck();      // email check is sufficent for a principal
		if(!check.isValid(m_impl->literalValue))
		{
			LOGIT_DEBUG("Wrong LiteralValue for type '1.3.6.1.4.1.311.20.2.3': " << m_impl->literalValue);
			return false;
		}
	}
	else if(m_impl->literalType == "1.3.6.1.5.2.2")  // KRB5PrincipalName
	{
		ValueCheck check = initEmailCheck();      // email check is sufficent for a principal
		if(!check.isValid(m_impl->literalValue))
		{
			LOGIT_DEBUG("Wrong LiteralValue for type '1.3.6.1.5.2.2': " << m_impl->literalValue);
			return false;
		}
	}
	else if(m_impl->literalType == "othername" ||
	        m_impl->literalType == "X400Name" ||
	        m_impl->literalType == "EdiPartyName")
	{
		// not realy supported, but ok
	}
	else
	{
		LOGIT_DEBUG("Unknown Type in LiteralValue: " << m_impl->literalType);
		return false;
	}
	return true;
}

std::vector<std::string>
LiteralValue::verify() const
{
	std::vector<std::string> result;

	if(m_impl->literalType == "email")
	{
		ValueCheck check = initEmailCheck();
		if(!check.isValid(m_impl->literalValue))
		{
			LOGIT_DEBUG("Wrong LiteralValue for type 'email': " << m_impl->literalValue);
			result.push_back(str::form("Wrong LiteralValue for type 'email': %s",
			                     m_impl->literalValue.c_str()));
		}
	}
	else if(m_impl->literalType == "URI")
	{
		ValueCheck check = initURICheck();
		if(!check.isValid(m_impl->literalValue))
		{
			LOGIT_DEBUG("Wrong LiteralValue for type 'URI': " << m_impl->literalValue);
			result.push_back(str::form("Wrong LiteralValue for type 'URI': %s",
			                     m_impl->literalValue.c_str()));
		}
	}
	else if(m_impl->literalType == "DNS")
	{
		ValueCheck check = initDNSCheck();
		if(!check.isValid(m_impl->literalValue))
		{
			LOGIT_DEBUG("Wrong LiteralValue for type 'DNS': " << m_impl->literalValue);
			result.push_back(str::form("Wrong LiteralValue for type 'DNS': %s",
			                     m_impl->literalValue.c_str()));
		}
	}
	else if(m_impl->literalType == "RID")
	{
		ValueCheck check = initOIDCheck();
		if(!check.isValid(m_impl->literalValue))
		{
			LOGIT_DEBUG("Wrong LiteralValue for type 'RID': " << m_impl->literalValue);
			result.push_back(str::form("Wrong LiteralValue for type 'RID': %s",
			                     m_impl->literalValue.c_str()));
		}
	}
	else if(m_impl->literalType == "IP")
	{
		ValueCheck check = initIP4Check();
		if(!check.isValid(m_impl->literalValue))
		{
			// IPv6 address is allowed too
			check = initIP6Check();
			if(!check.isValid(m_impl->literalValue))
			{
				LOGIT_DEBUG("Wrong LiteralValue for type 'IP': " << m_impl->literalValue);
				result.push_back(str::form("Wrong LiteralValue for type 'IP': %s",
									 m_impl->literalValue.c_str()));
			}
		}
	}
	else if(m_impl->literalType == "1.3.6.1.4.1.311.20.2.3")  // ms_upn
	{
		ValueCheck check = initEmailCheck();      // email check is sufficent for a principal
		if(!check.isValid(m_impl->literalValue))
		{
			LOGIT_DEBUG("Wrong LiteralValue for type '1.3.6.1.4.1.311.20.2.3': " << m_impl->literalValue);
			result.push_back(str::form("Wrong LiteralValue for type '1.3.6.1.4.1.311.20.2.3': %s",
			                     m_impl->literalValue.c_str()));
		}
	}
	else if(m_impl->literalType == "1.3.6.1.5.2.2")  // KRB5PrincipalName
	{
		ValueCheck check = initEmailCheck();      // email check is sufficent for a principal
		if(!check.isValid(m_impl->literalValue))
		{
			LOGIT_DEBUG("Wrong LiteralValue for type '1.3.6.1.5.2.2': " << m_impl->literalValue);
			result.push_back(str::form("Wrong LiteralValue for type '1.3.6.1.5.2.2': %s",
			                     m_impl->literalValue.c_str()));
		}
	}
	else if(m_impl->literalType == "othername" ||
	        m_impl->literalType == "X400Name" ||
	        m_impl->literalType == "EdiPartyName")
	{
		// not realy supported, but ok
	}
	else
	{
		LOGIT_DEBUG("Unknown Type in LiteralValue: " << m_impl->literalType);
		result.push_back(str::form("Unknown Type in LiteralValue: %s",
		                     m_impl->literalType.c_str()));
	}
	return result;
}

std::string
LiteralValue::toString() const
{
	return (m_impl->literalType + ":" + m_impl->literalValue);
}

std::vector<std::string>
LiteralValue::dump() const
{
	std::vector<std::string> result;
	result.push_back("LiteralValue::dump()");

	result.push_back(m_impl->literalType + ":" + m_impl->literalValue);

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
