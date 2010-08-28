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

#include  <ca-mgm/SubjectAlternativeNameExtension.hpp>
#include  <ca-mgm/CA.hpp>
#include  <ca-mgm/Exception.hpp>


#include  "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;

class SubjectAlternativeNameExtImpl
{
public:
	SubjectAlternativeNameExtImpl()
		: emailCopy(false)
		, altNameList(std::list<LiteralValue>())
	{}

	SubjectAlternativeNameExtImpl(bool copyEmail,
	                              const std::list<LiteralValue> &alternativeNameList)
		: emailCopy(copyEmail)
		, altNameList(alternativeNameList)
	{}

	SubjectAlternativeNameExtImpl(const SubjectAlternativeNameExtImpl& impl)
		: emailCopy(impl.emailCopy)
		, altNameList(impl.altNameList)
	{}

	~SubjectAlternativeNameExtImpl() {}

	SubjectAlternativeNameExtImpl* clone() const
	{
		return new SubjectAlternativeNameExtImpl(*this);
	}

	bool                           emailCopy;
	std::list<LiteralValue>     altNameList;

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
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, true), "subjectAltName");
	if(p)
	{
		std::vector<std::string>   sp   = PerlRegEx("\\s*,\\s*")
			.split(caConfig->getValue(type2Section(type, true), "subjectAltName"));

		if(0 == str::compareCI(sp[0], "critical"))  setCritical(true);

		std::vector<std::string>::const_iterator it = sp.begin();
		for(; it != sp.end(); ++it)
		{
			if((*it).find_first_of(":") != std::string::npos)
			{
				if(0 == str::compareCI(*it, "email:copy"))
					m_impl->emailCopy = true;
				else
				{
					try
					{
						LiteralValue lv = LiteralValue(*it);
						m_impl->altNameList.push_back(lv);
					}
					catch(ca_mgm::Exception& e)
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
	const std::list<LiteralValue> &alternativeNameList)
	: ExtensionBase()
	, m_impl(new SubjectAlternativeNameExtImpl(copyEmail, alternativeNameList))
{
	std::vector<std::string> r = checkLiteralValueList(alternativeNameList);
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		CA_MGM_THROW(ca_mgm::ValueException, r[0].c_str());
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
SubjectAlternativeNameExt::setAlternativeNameList(const std::list<LiteralValue> &alternativeNameList)
{
	std::vector<std::string> r = checkLiteralValueList(alternativeNameList);
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		CA_MGM_THROW(ca_mgm::ValueException, r[0].c_str());
	}
	m_impl->altNameList = alternativeNameList;
	setPresent(true);
}

bool
SubjectAlternativeNameExt::getCopyEmail() const
{
	if(!isPresent())
	{
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("SubjectAlternativeNameExt is not present."));
	}
	return m_impl->emailCopy;
}

std::list<LiteralValue>
SubjectAlternativeNameExt::getAlternativeNameList() const
{
	if(!isPresent())
	{
		CA_MGM_THROW(ca_mgm::RuntimeException,
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
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid SubjectAlternativeNameExt object."));
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
		std::string extString;

		if(isCritical())      extString += "critical,";
		if(m_impl->emailCopy) extString += "email:copy,";

		std::string val;
		std::list<LiteralValue>::const_iterator it = m_impl->altNameList.begin();
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
	std::vector<std::string> r = checkLiteralValueList(m_impl->altNameList);
	if(!r.empty())
	{
		LOGIT_DEBUG(r[0]);
		return false;
	}
	return true;
}

std::vector<std::string>
SubjectAlternativeNameExt::verify() const
{
	std::vector<std::string> result;

	if(!isPresent()) return result;

	if(!m_impl->emailCopy && m_impl->altNameList.empty())
	{
		result.push_back(std::string("invalid value for SubjectAlternativeNameExt"));
	}
	appendArray(result, checkLiteralValueList(m_impl->altNameList));

	LOGIT_DEBUG_STRINGARRAY("SubjectAlternativeNameExt::verify()", result);

	return result;
}

std::vector<std::string>
SubjectAlternativeNameExt::dump() const
{
	std::vector<std::string> result;
	result.push_back("SubjectAlternativeNameExt::dump()");

	appendArray(result, ExtensionBase::dump());
	if(!isPresent()) return result;

	result.push_back("email:copy = " + str::toString(m_impl->emailCopy));

	std::list< LiteralValue >::const_iterator it = m_impl->altNameList.begin();
	for(; it != m_impl->altNameList.end(); ++it)
	{
		appendArray(result, (*it).dump());
	}

	return result;
}

}
