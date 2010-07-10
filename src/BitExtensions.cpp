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

  File:       BitExtensions.cpp

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
using namespace blocxx;

class BitExtensionImpl
//
{
public:
	BitExtensionImpl()
		: value(0)
	{}

	BitExtensionImpl(uint32_t val)
		: value(val)
	{}

	BitExtensionImpl(const BitExtensionImpl& impl)
		: //COWIntrusiveCountableBase(impl) ,
		value(impl.value)
	{}

	~BitExtensionImpl() {}

	BitExtensionImpl* clone() const
	{
		return new BitExtensionImpl(*this);
	}

	uint32_t value;

};


// ===============================================================

BitExtension::BitExtension()
	: ExtensionBase()
	, m_impl(new BitExtensionImpl())
{}

BitExtension::BitExtension(uint32_t value)
	: ExtensionBase()
	, m_impl(new BitExtensionImpl(value))
{}

BitExtension::BitExtension(const BitExtension& extension)
	: ExtensionBase(extension)
	, m_impl(extension.m_impl)
{}

BitExtension::~BitExtension()
{}

BitExtension&
BitExtension::operator=(const BitExtension& extension)
{
	if(this == &extension) return *this;

	ExtensionBase::operator=(extension);
	m_impl = extension.m_impl;

	return *this;
}

void
BitExtension::setValue(uint32_t value)
{
	m_impl->value = value;
	setPresent(true);   // ??
}

uint32_t
BitExtension::getValue() const
{
	if(!isPresent())
	{
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("This BitExtension is not present."));
	}
	return m_impl->value;
}


// ###################################################################


KeyUsageExt::KeyUsageExt()
	: BitExtension()
{}

KeyUsageExt::KeyUsageExt(CAConfig* caConfig, Type type)
	: BitExtension()
{
	LOGIT_DEBUG("Parse KeyUsage");

	// These types are not supported by this object
	if(type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %d."), type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, true), "keyUsage");
	if(p)
	{
		uint32_t keyUsage = 0;

		std::string ku = caConfig->getValue(type2Section(type, true), "keyUsage");
		std::vector<std::string> sp = PerlRegEx("\\s*,\\s*").split(ku);

		if(0 == str::compareCI(sp[0], "critical")) setCritical(true);

		std::vector<std::string>::const_iterator it = sp.begin();
		for(; it != sp.end(); ++it)
		{
			if(0 == str::compareCI(*it, "digitalSignature"))      keyUsage |= digitalSignature;
			else if(0 == str::compareCI(*it, "nonRepudiation"))   keyUsage |= nonRepudiation;
			else if(0 == str::compareCI(*it, "keyEncipherment"))  keyUsage |= keyEncipherment;
			else if(0 == str::compareCI(*it, "dataEncipherment")) keyUsage |= dataEncipherment;
			else if(0 == str::compareCI(*it, "keyAgreement"))     keyUsage |= keyAgreement;
			else if(0 == str::compareCI(*it, "keyCertSign"))      keyUsage |= keyCertSign;
			else if(0 == str::compareCI(*it, "cRLSign"))          keyUsage |= cRLSign;
			else if(0 == str::compareCI(*it, "encipherOnly"))     keyUsage |= encipherOnly;
			else if(0 == str::compareCI(*it, "decipherOnly"))     keyUsage |= decipherOnly;
			else
				LOGIT_INFO("Unknown KeyUsage option: " << (*it));

		}
		setKeyUsage(keyUsage);
	}
	setPresent(p);
}

KeyUsageExt::KeyUsageExt(uint32_t keyUsage)
	: BitExtension(keyUsage)
{
	if(!validKeyUsage(keyUsage))
	{
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid value for keyUsage."));
	}
	setPresent(true);
}

KeyUsageExt::KeyUsageExt(const KeyUsageExt& extension)
	: BitExtension(extension)
{}

KeyUsageExt::~KeyUsageExt()
{}


KeyUsageExt&
KeyUsageExt::operator=(const KeyUsageExt& extension)
{
	if(this == &extension) return *this;

	BitExtension::operator=(extension);

	return *this;
}

void
KeyUsageExt::setKeyUsage(uint32_t keyUsage)
{
	if(!validKeyUsage(keyUsage))
	{
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid value for keyUsage."));
	}
	setValue(keyUsage);
	setPresent(true);
}

uint32_t
KeyUsageExt::getKeyUsage() const
{
	if(!isPresent())
	{
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("KeyUsageExt is not present."));
	}
	return getValue();
}

bool
KeyUsageExt::isEnabledFor(KeyUsage ku) const
{
	if(!isPresent())
	{
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("KeyUsageExt is not present."));
	}

	return !!(getValue() & ku);
}

void
KeyUsageExt::commit2Config(CA& ca, Type type) const
{
	if(!valid())
	{
		LOGIT_ERROR("invalid KeyUsageExt object");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid KeyUsageExt object."));
	}

	// This extension is not supported by type CRL
	if(type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %d."), type).c_str());
	}

	if(isPresent())
	{
		std::string keyUsageString;

		if(isCritical()) keyUsageString += "critical,";

		if(!!(getValue() & KeyUsageExt::digitalSignature))
		{
			keyUsageString += "digitalSignature,";
		}
		if(!!(getValue() & KeyUsageExt::nonRepudiation))
		{
			keyUsageString += "nonRepudiation,";
		}
		if(!!(getValue() & KeyUsageExt::keyEncipherment))
		{
			keyUsageString += "keyEncipherment,";
		}
		if(!!(getValue() & KeyUsageExt::dataEncipherment))
		{
			keyUsageString += "dataEncipherment,";
		}
		if(!!(getValue() & KeyUsageExt::keyAgreement))
		{
			keyUsageString += "keyAgreement,";
		}
		if(!!(getValue() & KeyUsageExt::keyCertSign))
		{
			keyUsageString += "keyCertSign,";
		}
		if(!!(getValue() & KeyUsageExt::cRLSign))
		{
			keyUsageString += "cRLSign,";
		}
		if(!!(getValue() & KeyUsageExt::encipherOnly))
		{
			keyUsageString += "encipherOnly,";
		}
		if(!!(getValue() & KeyUsageExt::decipherOnly))
		{
			keyUsageString += "decipherOnly,";
		}

		ca.getConfig()->setValue(type2Section(type, true), "keyUsage",
		                         keyUsageString.erase(keyUsageString.length()-1));
	}
	else
	{
		ca.getConfig()->deleteValue(type2Section(type, true), "keyUsage");
	}
}

bool
KeyUsageExt::valid() const
{
	if(!isPresent()) return true;

	if(!validKeyUsage(getValue())) return false;

	return true;
}

std::vector<std::string>
KeyUsageExt::verify() const
{
	std::vector<std::string> result;

	if(!isPresent()) return result;

	if(!validKeyUsage(getValue()))
	{
		result.push_back(str::form("invalid value '%d' for keyUsage", getValue()));
	}

	LOGIT_DEBUG_STRINGARRAY("KeyUsageExt::verify()", result);
	return result;
}

std::vector<std::string>
KeyUsageExt::dump() const
{
	std::vector<std::string> result;
	result.push_back("KeyUsageExt::dump()");

	appendArray(result, ExtensionBase::dump());
	if(!isPresent()) return result;

	result.push_back("KeyUsage = " + str::hexstring(getValue(), 6));

	return result;
}


bool
KeyUsageExt::validKeyUsage(uint32_t keyUsage) const
{
	uint32_t mask = 0x80FF;
	if( (keyUsage&mask) != keyUsage || keyUsage == 0)
	{
		return false;
	}
	return true;
}


// ###################################################################


NsCertTypeExt::NsCertTypeExt()
	: BitExtension()
{}

NsCertTypeExt::NsCertTypeExt(CAConfig* caConfig, Type type)
	: BitExtension()
{
	LOGIT_DEBUG("Parse NsCertType");

	// These types are not supported by this object
	if(type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, true), "nsCertType");
	if(p)
	{
		uint32_t bits = 0;

		std::string ct = caConfig->getValue(type2Section(type, true), "nsCertType");
		std::vector<std::string> sp = PerlRegEx("\\s*,\\s*").split(ct);

		if(0 == str::compareCI(sp[0], "critical")) setCritical(true);

		std::vector<std::string>::const_iterator it = sp.begin();
		for(; it != sp.end(); ++it)
		{
			if(0 == str::compareCI(*it, "client"))        bits |= client;
			else if(0 == str::compareCI(*it, "server"))   bits |= server;
			else if(0 == str::compareCI(*it, "email"))    bits |= email;
			else if(0 == str::compareCI(*it, "objsign"))  bits |= objsign;
			else if(0 == str::compareCI(*it, "reserved")) bits |= reserved;
			else if(0 == str::compareCI(*it, "sslCA"))    bits |= sslCA;
			else if(0 == str::compareCI(*it, "emailCA"))  bits |= emailCA;
			else if(0 == str::compareCI(*it, "objCA"))    bits |= objCA;
			else
				LOGIT_INFO("Unknown NsCertType option: " << (*it));
		}
		setNsCertType(bits);
	}
	setPresent(p);
}

NsCertTypeExt::NsCertTypeExt(uint32_t nsCertTypes)
	: BitExtension(nsCertTypes)
{
	if(nsCertTypes > 0xFF || nsCertTypes == 0)
	{
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid value for NsCertTypeExt."));
	}
	setPresent(true);
}

NsCertTypeExt::NsCertTypeExt(const NsCertTypeExt& extension)
	: BitExtension(extension)
{}

NsCertTypeExt::~NsCertTypeExt()
{}


NsCertTypeExt&
NsCertTypeExt::operator=(const NsCertTypeExt& extension)
{
	if(this == &extension) return *this;

	BitExtension::operator=(extension);

	return *this;
}

void
NsCertTypeExt::setNsCertType(uint32_t nsCertTypes)
{
	if(nsCertTypes > 0xFF || nsCertTypes == 0)
	{
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Invalid value for NsCertTypeExt: %1."), nsCertTypes).c_str());
	}
	setValue(nsCertTypes);
	setPresent(true);
}

uint32_t
NsCertTypeExt::getNsCertType() const
{
	if(!isPresent())
	{
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("NsCertTypeExt is not present."));
	}
	return getValue();
}

bool
NsCertTypeExt::isEnabledFor(NsCertType nsCertType) const
{
	// if ! isPresent() ... throw exceptions?
	if(!isPresent()) return false;

	return !!(getValue() & nsCertType);
}

void
NsCertTypeExt::commit2Config(CA& ca, Type type) const
{
	if(!valid())
	{
		LOGIT_ERROR("invalid NsCertTypeExt object");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid NsCertTypeExt object."));
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
		std::string nsCertTypeString;

		if(isCritical()) nsCertTypeString += "critical,";

		if(!!(getValue() & NsCertTypeExt::client))
		{
			nsCertTypeString += "client,";
		}
		if(!!(getValue() & NsCertTypeExt::server))
		{
			nsCertTypeString += "server,";
		}
		if(!!(getValue() & NsCertTypeExt::email))
		{
			nsCertTypeString += "email,";
		}
		if(!!(getValue() & NsCertTypeExt::objsign))
		{
			nsCertTypeString += "objsign,";
		}
		if(!!(getValue() & NsCertTypeExt::reserved))
		{
			nsCertTypeString += "reserved,";
		}
		if(!!(getValue() & NsCertTypeExt::sslCA))
		{
			nsCertTypeString += "sslCA,";
		}
		if(!!(getValue() & NsCertTypeExt::emailCA))
		{
			nsCertTypeString += "emailCA,";
		}
		if(!!(getValue() & NsCertTypeExt::objCA))
		{
			nsCertTypeString += "objCA,";
		}

		ca.getConfig()->setValue(type2Section(type, true), "nsCertType",
		                         nsCertTypeString.erase(nsCertTypeString.length()-1));
	}
	else
	{
		ca.getConfig()->deleteValue(type2Section(type, true), "nsCertType");
	}
}

bool
NsCertTypeExt::valid() const
{
	if(!isPresent()) return true;

	if(getValue() > 0xFF || getValue() == 0) return false;

	return true;
}

std::vector<std::string>
NsCertTypeExt::verify() const
{
	std::vector<std::string> result;

	if(!isPresent()) return result;

	if(getValue() > 0xFF || getValue() == 0)
	{
		result.push_back(str::form("invalid value '%d' for nsCertType", getValue()));
	}
	LOGIT_DEBUG_STRINGARRAY("NsCertTypeExt::verify()", result);
	return result;
}

std::vector<std::string>
NsCertTypeExt::dump() const
{
	std::vector<std::string> result;
	result.push_back("NsCertTypeExt::dump()");

	appendArray(result, ExtensionBase::dump());
	if(!isPresent()) return result;

	result.push_back("NsCertType = " + str::hexstring( getValue(), 4));

	return result;
}

}

