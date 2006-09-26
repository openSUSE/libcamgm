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
#include  <blocxx/Format.hpp>
#include  <blocxx/COWIntrusiveCountableBase.hpp>

#include  "Utils.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;

class SubjectKeyIdentifierExtImpl : public blocxx::COWIntrusiveCountableBase
{
	public:
	SubjectKeyIdentifierExtImpl()
		: autodetect(false)
		, keyid(String())
	{}

	SubjectKeyIdentifierExtImpl(bool autoDetect, const String& keyID)
		: autodetect(autoDetect)
		, keyid(keyID)
	{}

	SubjectKeyIdentifierExtImpl(const SubjectKeyIdentifierExtImpl& impl)
		: COWIntrusiveCountableBase(impl)
		, autodetect(impl.autodetect)
		, keyid(impl.keyid)
	{}

	~SubjectKeyIdentifierExtImpl() {}

	SubjectKeyIdentifierExtImpl* clone() const
	{
		return new SubjectKeyIdentifierExtImpl(*this);
	}

	bool   autodetect;  // ??
	String keyid;
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
		BLOCXX_THROW(limal::ValueException,
		             Format(__("Wrong type: %1."), type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, true), "subjectKeyIdentifier");
	if(p)
	{
		String        str;

		StringArray   sp   = PerlRegEx("\\s*,\\s*")
			.split(caConfig->getValue(type2Section(type, true), "subjectKeyIdentifier"));

		if(sp[0].equalsIgnoreCase("critical"))
		{
			setCritical(true);
			str = sp[1];
		}
		else
		{
			str = sp[0];
		}

		if(str.equalsIgnoreCase("hash"))
		{
			m_impl->autodetect = true;
			m_impl->keyid      = String();
		}
		else
		{
			m_impl->autodetect = false;
			m_impl->keyid      = str;
		}
	}
	setPresent(p);
}

SubjectKeyIdentifierExt::SubjectKeyIdentifierExt(bool autoDetect, const String& keyid)
	: ExtensionBase()
	, m_impl(new SubjectKeyIdentifierExtImpl(autoDetect, keyid))
{
	if(!keyid.empty() &&
	   !initHexCheck().isValid(keyid))
	{
		LOGIT_ERROR("invalid KeyID");
		BLOCXX_THROW(limal::ValueException,
		             __("Invalid KeyID"));
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
                                                 const String& keyId)
{
	if(!keyId.empty() && !initHexCheck().isValid(keyId))
	{
		LOGIT_ERROR("invalid KeyID");
		BLOCXX_THROW(limal::ValueException,
		             __("Invalid KeyID"));
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
		BLOCXX_THROW(limal::RuntimeException,
		             __("SubjectKeyIdentifierExt is not present"));
	}
	return m_impl->autodetect;
}

blocxx::String
SubjectKeyIdentifierExt::getKeyID() const
{
	if(!isPresent())
	{
		BLOCXX_THROW(limal::RuntimeException,
		             __("SubjectKeyIdentifierExt is not present"));
	}
	return m_impl->keyid;
}


void
SubjectKeyIdentifierExt::commit2Config(CA& ca, Type type) const
{
	if(!valid())
	{
		LOGIT_ERROR("invalid SubjectKeyIdentifierExt object");
		BLOCXX_THROW(limal::ValueException,
		             __("Invalid SubjectKeyIdentifierExt object"));
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
		String extString;

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
		LOGIT_DEBUG(String("Wrong value for SubjectKeyIdentifierExt: ") +
		            Format("autodetect(%1), keyId(%2)",
		                   m_impl->autodetect?"true":"false", m_impl->keyid));
		return false;
	}

	if(m_impl->autodetect && !m_impl->keyid.empty())
	{
		LOGIT_DEBUG(String("Wrong value for SubjectKeyIdentifierExt: ") +
		            Format("autodetect(%1), keyId(%2)",
		                   m_impl->autodetect?"true":"false", m_impl->keyid));
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

blocxx::StringArray
SubjectKeyIdentifierExt::verify() const
{
	StringArray result;

	if(!isPresent()) return result;

	if(!m_impl->autodetect && m_impl->keyid.empty())
	{
		result.append(String("Wrong value for SubjectKeyIdentifierExt: ") +
		              Format("autodetect(%1), keyId(%2)", 
		                     m_impl->autodetect?"true":"false",
		                     m_impl->keyid.c_str()).toString());
	}

	if(m_impl->autodetect && !m_impl->keyid.empty())
	{
		result.append(String("Wrong value for SubjectKeyIdentifierExt: ") +
		              Format("autodetect(%1), keyId(%2)", 
		                     m_impl->autodetect?"true":"false",
		                     m_impl->keyid.c_str()).toString());
	}
	if(!m_impl->keyid.empty())
	{
		ValueCheck check = initHexCheck();
		if(!check.isValid(m_impl->keyid))
		{
			result.append(Format("Wrong keyID in SubjectKeyIdentifierExt: %1",
			                     m_impl->keyid.c_str()).toString());
		}
	}
	LOGIT_DEBUG_STRINGARRAY("SubjectKeyIdentifierExt::verify()", result);
	return result;
}

blocxx::StringArray
SubjectKeyIdentifierExt::dump() const
{
	StringArray result;
	result.append("SubjectKeyIdentifierExt::dump()");

	result.appendArray(ExtensionBase::dump());
	if(!isPresent()) return result;

	result.append("Autodetect = " + Bool(m_impl->autodetect).toString());
	result.append("KeyID = " + m_impl->keyid);

	return result;
}

}
}
