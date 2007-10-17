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

  File:       SubjectAlternativeNameExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/SubjectAlternativeNameExtension.hpp>
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

class SubjectAlternativeNameExtImpl : public blocxx::COWIntrusiveCountableBase
{
public:
	SubjectAlternativeNameExtImpl()
		: emailCopy(false)
		, altNameList(blocxx::List<LiteralValue>())
	{}

	SubjectAlternativeNameExtImpl(bool copyEmail,
	                              const blocxx::List<LiteralValue> &alternativeNameList)
		: emailCopy(copyEmail)
		, altNameList(alternativeNameList)
	{}

	SubjectAlternativeNameExtImpl(const SubjectAlternativeNameExtImpl& impl)
		: COWIntrusiveCountableBase(impl)
		, emailCopy(impl.emailCopy)
		, altNameList(impl.altNameList)
	{}

	~SubjectAlternativeNameExtImpl() {}

	SubjectAlternativeNameExtImpl* clone() const
	{
		return new SubjectAlternativeNameExtImpl(*this);
	}

	bool                           emailCopy;
	blocxx::List<LiteralValue>     altNameList;

};

SubjectAlternativeNameExt::SubjectAlternativeNameExt()
	: ExtensionBase()
	, m_impl(new SubjectAlternativeNameExtImpl())

{}

SubjectAlternativeNameExt::SubjectAlternativeNameExt(CAConfig* caConfig, Type type)
	: ExtensionBase()
	, m_impl(new SubjectAlternativeNameExtImpl())
{
	// These types are not supported by this object
	if(type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		BLOCXX_THROW(limal::ValueException,
		             Format(__("Wrong type: %1."), type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, true), "subjectAltName");
	if(p)
	{
		StringArray   sp   = PerlRegEx("\\s*,\\s*")
			.split(caConfig->getValue(type2Section(type, true), "subjectAltName"));

		if(sp[0].equalsIgnoreCase("critical"))  setCritical(true);

		StringArray::const_iterator it = sp.begin();
		for(; it != sp.end(); ++it)
		{
			if((*it).indexOf(":") != String::npos)
			{
				if((*it).equalsIgnoreCase("email:copy"))
					m_impl->emailCopy = true;
				else
				{
					try
					{
						LiteralValue lv = LiteralValue(*it);
						m_impl->altNameList.push_back(lv);
					}
					catch(blocxx::Exception& e)
					{
						LOGIT_ERROR("invalid value: " << *it << "\n" <<e);
					}
				}
			}
		}
	}
	setPresent(p);
}

SubjectAlternativeNameExt::SubjectAlternativeNameExt(bool copyEmail,
	const blocxx::List<LiteralValue> &alternativeNameList)
	: ExtensionBase()
	, m_impl(new SubjectAlternativeNameExtImpl(copyEmail, alternativeNameList))
{
	StringArray r = checkLiteralValueList(alternativeNameList);
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(limal::ValueException, r[0].c_str());
	}
	setPresent(true);
}

SubjectAlternativeNameExt::SubjectAlternativeNameExt(const SubjectAlternativeNameExt& extension)
	: ExtensionBase(extension),
	m_impl(extension.m_impl)
{}


SubjectAlternativeNameExt::~SubjectAlternativeNameExt()
{}


SubjectAlternativeNameExt&
SubjectAlternativeNameExt::operator=(const SubjectAlternativeNameExt& extension)
{
	if(this == &extension) return *this;

	ExtensionBase::operator=(extension);

	m_impl = extension.m_impl;

	return *this;
}

void
SubjectAlternativeNameExt::setCopyEmail(bool copyEmail)
{
	m_impl->emailCopy = copyEmail;
	setPresent(true);
}

void
SubjectAlternativeNameExt::setAlternativeNameList(const blocxx::List<LiteralValue> &alternativeNameList)
{
	StringArray r = checkLiteralValueList(alternativeNameList);
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(limal::ValueException, r[0].c_str());
	}
	m_impl->altNameList = alternativeNameList;
	setPresent(true);
}

bool
SubjectAlternativeNameExt::getCopyEmail() const
{
	if(!isPresent())
	{
		BLOCXX_THROW(limal::RuntimeException,
		             __("SubjectAlternativeNameExt is not present."));
	}
	return m_impl->emailCopy;
}

blocxx::List<LiteralValue>
SubjectAlternativeNameExt::getAlternativeNameList() const
{
	if(!isPresent())
	{
		BLOCXX_THROW(limal::RuntimeException,
		             __("SubjectAlternativeNameExt is not present."));
	}
	return m_impl->altNameList;
}


void
SubjectAlternativeNameExt::commit2Config(CA& ca, Type type) const
{
	if(!valid())
	{
		LOGIT_ERROR("invalid SubjectAlternativeNameExt object");
		BLOCXX_THROW(limal::ValueException,
		             __("Invalid SubjectAlternativeNameExt object."));
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

		if(isCritical())      extString += "critical,";
		if(m_impl->emailCopy) extString += "email:copy,";

		String val;
		blocxx::List<LiteralValue>::const_iterator it = m_impl->altNameList.begin();
		for(int j = 0;it != m_impl->altNameList.end(); ++it, ++j)
		{
			val = "";
			if( (val = (*it).commit2Config(ca, type, j)) != "")
			{
				extString += val+",";
			}
		}

		ca.getConfig()->setValue(type2Section(type, true), "subjectAltName",
		                         extString.erase(extString.length()-1));
	}
	else
	{
		ca.getConfig()->deleteValue(type2Section(type, true), "subjectAltName");
	}
}

bool
SubjectAlternativeNameExt::valid() const
{
	if(!isPresent()) return true;

	if(!m_impl->emailCopy && m_impl->altNameList.empty())
	{
		LOGIT_DEBUG("return SubjectAlternativeNameExt::::valid() is false");
		return false;
	}
	StringArray r = checkLiteralValueList(m_impl->altNameList);
	if(!r.empty())
	{
		LOGIT_DEBUG(r[0]);
		return false;
	}
	return true;
}

blocxx::StringArray
SubjectAlternativeNameExt::verify() const
{
	StringArray result;

	if(!isPresent()) return result;

	if(!m_impl->emailCopy && m_impl->altNameList.empty())
	{
		result.append(String("invalid value for SubjectAlternativeNameExt"));
	}
	result.appendArray(checkLiteralValueList(m_impl->altNameList));

	LOGIT_DEBUG_STRINGARRAY("SubjectAlternativeNameExt::verify()", result);

	return result;
}

blocxx::StringArray
SubjectAlternativeNameExt::dump() const
{
	StringArray result;
	result.append("SubjectAlternativeNameExt::dump()");

	result.appendArray(ExtensionBase::dump());
	if(!isPresent()) return result;

	result.append("email:copy = " + Bool(m_impl->emailCopy).toString());

	blocxx::List< LiteralValue >::const_iterator it = m_impl->altNameList.begin();
	for(; it != m_impl->altNameList.end(); ++it)
	{
		result.appendArray((*it).dump());
	}

	return result;
}

}
}
