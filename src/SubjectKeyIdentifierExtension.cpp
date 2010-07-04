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

  File:       SubjectKeyIdentifierExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/SubjectKeyIdentifierExtension.hpp>
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>



#include  "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;
using namespace blocxx;

class SubjectKeyIdentifierExtImpl
{
public:
	SubjectKeyIdentifierExtImpl()
		: autodetect(false)
		, keyid(std::string())
	{}

	SubjectKeyIdentifierExtImpl(bool autoDetect, const std::string& keyID)
		: autodetect(autoDetect)
		, keyid(keyID)
	{}

	SubjectKeyIdentifierExtImpl(const SubjectKeyIdentifierExtImpl& impl)
		: autodetect(impl.autodetect)
		, keyid(impl.keyid)
	{}

	~SubjectKeyIdentifierExtImpl() {}

	SubjectKeyIdentifierExtImpl* clone() const
	{
		return new SubjectKeyIdentifierExtImpl(*this);
	}

	bool   autodetect;  // ??
	std::string keyid;
};


SubjectKeyIdentifierExt::SubjectKeyIdentifierExt()
	: ExtensionBase()
	, m_impl(new SubjectKeyIdentifierExtImpl())
{}

SubjectKeyIdentifierExt::SubjectKeyIdentifierExt(CAConfig* caConfig, Type type)
	: ExtensionBase()
	, m_impl(new SubjectKeyIdentifierExtImpl())
{
	// These types are not supported by this object
	if(type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		BLOCXX_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, true), "subjectKeyIdentifier");
	if(p)
	{
		std::string        str;

		std::vector<std::string>   sp   = PerlRegEx("\\s*,\\s*")
			.split(caConfig->getValue(type2Section(type, true), "subjectKeyIdentifier"));

		if(0 == str::compareCI(sp[0], "critical"))
		{
			setCritical(true);
			str = sp[1];
		}
		else
		{
			str = sp[0];
		}

		if(0 == str::compareCI(str, "hash"))
		{
			m_impl->autodetect = true;
			m_impl->keyid      = std::string();
		}
		else
		{
			m_impl->autodetect = false;
			m_impl->keyid      = str;
		}
	}
	setPresent(p);
}

SubjectKeyIdentifierExt::SubjectKeyIdentifierExt(bool autoDetect, const std::string& keyid)
	: ExtensionBase()
	, m_impl(new SubjectKeyIdentifierExtImpl(autoDetect, keyid))
{
	if(!keyid.empty() &&
	   !initHexCheck().isValid(keyid))
	{
		LOGIT_ERROR("invalid KeyID");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("Invalid KeyID."));
	}
	setPresent(true);
}

SubjectKeyIdentifierExt::SubjectKeyIdentifierExt(const SubjectKeyIdentifierExt& extension)
	: ExtensionBase(extension)
	, m_impl(extension.m_impl)
{}

SubjectKeyIdentifierExt::~SubjectKeyIdentifierExt()
{}


SubjectKeyIdentifierExt&
SubjectKeyIdentifierExt::operator=(const SubjectKeyIdentifierExt& extension)
{
	if(this == &extension) return *this;

	ExtensionBase::operator=(extension);

	m_impl = extension.m_impl;

	return *this;
}

void
SubjectKeyIdentifierExt::setSubjectKeyIdentifier(bool autoDetect,
	const std::string& keyId)
{
	if(!keyId.empty() && !initHexCheck().isValid(keyId))
	{
		LOGIT_ERROR("invalid KeyID");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("Invalid KeyID."));
	}
	m_impl->autodetect = autoDetect;
	m_impl->keyid      = keyId;
	setPresent(true);
}

bool
SubjectKeyIdentifierExt::isAutoDetectionEnabled() const
{
	if(!isPresent())
	{
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             __("SubjectKeyIdentifierExt is not present."));
	}
	return m_impl->autodetect;
}

std::string
SubjectKeyIdentifierExt::getKeyID() const
{
	if(!isPresent())
	{
		BLOCXX_THROW(ca_mgm::RuntimeException,
		             __("SubjectKeyIdentifierExt is not present."));
	}
	return m_impl->keyid;
}


void
SubjectKeyIdentifierExt::commit2Config(CA& ca, Type type) const
{
	if(!valid())
	{
		LOGIT_ERROR("invalid SubjectKeyIdentifierExt object");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("Invalid SubjectKeyIdentifierExt object."));
	}

	// This extension is not supported by type CRL
	if(type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		BLOCXX_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	if(isPresent())
	{
		std::string extString;

		if(isCritical())         extString += "critical,";
		if(m_impl->autodetect)   extString += "hash";
		else                     extString += m_impl->keyid;

		ca.getConfig()->setValue(type2Section(type, true),
		                         "subjectKeyIdentifier", extString);
	}
	else
	{
		ca.getConfig()->deleteValue(type2Section(type, true),
		                            "subjectKeyIdentifier");
	}
}

bool
SubjectKeyIdentifierExt::valid() const
{
	if(!isPresent()) return true;

	if(!m_impl->autodetect && m_impl->keyid.empty())
	{
		LOGIT_DEBUG(std::string("Wrong value for SubjectKeyIdentifierExt: ") +
		            str::form("autodetect(%s), keyId(%s)",
		                   m_impl->autodetect?"true":"false", m_impl->keyid.c_str()));
		return false;
	}

	if(m_impl->autodetect && !m_impl->keyid.empty())
	{
		LOGIT_DEBUG(std::string("Wrong value for SubjectKeyIdentifierExt: ") +
		            str::form("autodetect(%s), keyId(%s)",
		                   m_impl->autodetect?"true":"false", m_impl->keyid.c_str()));
		return false;
	}
	if(!m_impl->keyid.empty())
	{
		ValueCheck check = initHexCheck();
		if(!check.isValid(m_impl->keyid))
		{
			LOGIT_DEBUG("Wrong keyID in SubjectKeyIdentifierExt:" << m_impl->keyid);
			return false;
		}
	}
	return true;
}

std::vector<std::string>
SubjectKeyIdentifierExt::verify() const
{
	std::vector<std::string> result;

	if(!isPresent()) return result;

	if(!m_impl->autodetect && m_impl->keyid.empty())
	{
		result.push_back(std::string("Wrong value for SubjectKeyIdentifierExt: ") +
		              str::form("autodetect(%s), keyId(%s)",
		                     m_impl->autodetect?"true":"false",
		                     m_impl->keyid.c_str()));
	}

	if(m_impl->autodetect && !m_impl->keyid.empty())
	{
		result.push_back(std::string("Wrong value for SubjectKeyIdentifierExt: ") +
		              str::form("autodetect(%s), keyId(%s)",
		                     m_impl->autodetect?"true":"false",
		                     m_impl->keyid.c_str()));
	}
	if(!m_impl->keyid.empty())
	{
		ValueCheck check = initHexCheck();
		if(!check.isValid(m_impl->keyid))
		{
			result.push_back(str::form("Wrong keyID in SubjectKeyIdentifierExt: %s",
			                     m_impl->keyid.c_str()));
		}
	}
	LOGIT_DEBUG_STRINGARRAY("SubjectKeyIdentifierExt::verify()", result);
	return result;
}

std::vector<std::string>
SubjectKeyIdentifierExt::dump() const
{
	std::vector<std::string> result;
	result.push_back("SubjectKeyIdentifierExt::dump()");

	appendArray(result, ExtensionBase::dump());
	if(!isPresent()) return result;

	result.push_back("Autodetect = " + str::toString(m_impl->autodetect));
	result.push_back("KeyID = " + m_impl->keyid);

	return result;
}

}
