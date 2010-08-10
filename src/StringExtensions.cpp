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

  File:       StringExtensions.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/StringExtensions.hpp>
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>



#include  "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;

class StringExtensionImpl
{
public:
	StringExtensionImpl()
		: value(std::string())
	{}

	StringExtensionImpl(const std::string &v)
		: value(v)
	{}

	StringExtensionImpl(const StringExtensionImpl& impl)
		: value(impl.value)
	{}

	~StringExtensionImpl() {}

	StringExtensionImpl* clone() const
	{
		return new StringExtensionImpl(*this);
	}

	std::string value;

};

StringExtension::StringExtension()
	: ExtensionBase()
	, m_impl(new StringExtensionImpl())
{}

StringExtension::~StringExtension()
{}


//    protected:

StringExtension::StringExtension(const std::string &v )
	: ExtensionBase()
	, m_impl(new StringExtensionImpl(v))
{}

StringExtension::StringExtension(const StringExtension& extension)
	: ExtensionBase(extension)
	, m_impl(extension.m_impl)
{}

StringExtension&
StringExtension::operator=(const StringExtension& extension)
{
	if(this == &extension) return *this;

	ExtensionBase::operator=(extension);
	m_impl = extension.m_impl;

	return *this;
}


// #################################################################

NsBaseUrlExt::NsBaseUrlExt(const std::string &v)
	: StringExtension(v)
{
	if(!initURICheck().isValid(v))
	{
		LOGIT_ERROR("invalid value for NsBaseUrlExt");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid value for NsBaseUrlExt."));
	}
	setPresent(true);
}

NsBaseUrlExt::NsBaseUrlExt(CAConfig* caConfig, Type type)
	: StringExtension(std::string())
{
	// These types are not supported by this object
	if(type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, true), "nsBaseUrl");
	if(p)
	{
		std::vector<std::string>   sp   = PerlRegEx("\\s*,\\s*")
			.split(caConfig->getValue(type2Section(type, true), "nsBaseUrl"));
		if(0 == str::compareCI(sp[0], "critical"))
		{
			setCritical(true);
			m_impl->value = sp[1];
		}
		else
		{
			m_impl->value = sp[0];
		}
	}
	setPresent(p);
}

NsBaseUrlExt::NsBaseUrlExt(const NsBaseUrlExt &extension)
	: StringExtension(extension)
{}

NsBaseUrlExt::~NsBaseUrlExt()
{}

NsBaseUrlExt&
NsBaseUrlExt::operator=(const NsBaseUrlExt& extension)
{
	if(this == &extension) return *this;

	StringExtension::operator=(extension);

	return *this;
}

void
NsBaseUrlExt::setValue(const std::string &v)
{
	if(!initURICheck().isValid(v))
	{
		LOGIT_ERROR("invalid value for NsBaseUrlExt");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid value for NsBaseUrlExt."));
	}
	m_impl->value = v;
	setPresent(true);
}

std::string
NsBaseUrlExt::getValue() const
{
	if(!isPresent())
	{
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("NsBaseUrlExt is not present."));
	}
	return m_impl->value;
}

void
NsBaseUrlExt::commit2Config(CA& ca, Type type) const
{
	if(!valid())
	{
		LOGIT_ERROR("invalid NsBaseUrlExt object");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid NsBaseUrlExt object."));
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

		if(isCritical()) extString += "critical,";
		extString += m_impl->value;

		ca.getConfig()->setValue(type2Section(type, true), "nsBaseUrl", extString);
	}
	else
	{
		ca.getConfig()->deleteValue(type2Section(type, true), "nsBaseUrl");
	}
}

bool
NsBaseUrlExt::valid() const
{
	if(!isPresent()) return true;

	if(!initURICheck().isValid(m_impl->value))
	{
		LOGIT_DEBUG("Wrong value for NsBaseUrlExt:" << m_impl->value);
		return false;
	}
	return true;
}

std::vector<std::string>
NsBaseUrlExt::verify() const
{
	std::vector<std::string> result;

	if(!isPresent()) return result;

	if(!initURICheck().isValid(m_impl->value)) {
		LOGIT_DEBUG("Wrong value for NsBaseUrlExt:" << m_impl->value);
		result.push_back(str::form("Wrong value for NsBaseUrlExt: %s", m_impl->value.c_str()));
	}
	LOGIT_DEBUG_STRINGARRAY("NsBaseUrlExt::verify()", result);
	return result;
}

std::vector<std::string>
NsBaseUrlExt::dump() const
{
	std::vector<std::string> result;
	result.push_back("NsBaseUrlExt::dump()");

	appendArray(result, ExtensionBase::dump());
	if(!isPresent()) return result;

	result.push_back("URL = " + m_impl->value);

	return result;
}


// private:
NsBaseUrlExt::NsBaseUrlExt()
	: StringExtension(std::string())
{}


// #################################################################

NsRevocationUrlExt::NsRevocationUrlExt(const std::string &v)
	: StringExtension(v)
{
	if(!initURICheck().isValid(v)) {
		LOGIT_ERROR("invalid value for NsRevocationUrlExt");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid value for NsRevocationUrlExt."));
	}
	setPresent(true);
}

NsRevocationUrlExt::NsRevocationUrlExt(CAConfig* caConfig, Type type)
	: StringExtension(std::string())
{
	// These types are not supported by this object
	if(type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, true), "nsRevocationUrl");
	if(p) {
		std::vector<std::string>   sp   = PerlRegEx("\\s*,\\s*")
			.split(caConfig->getValue(type2Section(type, true), "nsRevocationUrl"));
		if(0 == str::compareCI(sp[0], "critical")) {
			setCritical(true);
			m_impl->value = sp[1];
		} else {
			m_impl->value = sp[0];
		}
	}
	setPresent(p);
}

NsRevocationUrlExt::NsRevocationUrlExt(const NsRevocationUrlExt &extension)
	: StringExtension(extension)
{}

NsRevocationUrlExt::~NsRevocationUrlExt()
{}

NsRevocationUrlExt&
NsRevocationUrlExt::operator=(const NsRevocationUrlExt& extension)
{
	if(this == &extension) return *this;

	StringExtension::operator=(extension);

	return *this;
}

void
NsRevocationUrlExt::setValue(const std::string &v)
{
	if(!initURICheck().isValid(v)) {
		LOGIT_ERROR("invalid value for NsRevocationUrlExt");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid value for NsRevocationUrlExt."));
	}
	m_impl->value = v;
	setPresent(true);
}

std::string
NsRevocationUrlExt::getValue() const
{
	if(!isPresent()) {
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("NsRevocationUrlExt is not present."));
	}
	return m_impl->value;
}

void
NsRevocationUrlExt::commit2Config(CA& ca, Type type) const
{
	if(!valid()) {
		LOGIT_ERROR("invalid NsRevocationUrlExt object");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid NsRevocationUrlExt object."));
	}

	// This extension is not supported by type CRL
	if(type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	if(isPresent()) {
		std::string extString;

		if(isCritical()) extString += "critical,";
		extString += m_impl->value;

		ca.getConfig()->setValue(type2Section(type, true), "nsRevocationUrl", extString);
	} else {
		ca.getConfig()->deleteValue(type2Section(type, true), "nsRevocationUrl");
	}
}

std::vector<std::string>
NsRevocationUrlExt::verify() const
{
	std::vector<std::string> result;

	if(!isPresent()) return result;

	if(!initURICheck().isValid(m_impl->value)) {
		LOGIT_DEBUG("Wrong value for NsRevocationUrlExt:" << m_impl->value);
		result.push_back(str::form("Wrong value for NsRevocationUrlExt: %s", m_impl->value.c_str()));
	}
	LOGIT_DEBUG_STRINGARRAY("NsRevocationUrlExt::verify()", result);
	return result;
}

bool
NsRevocationUrlExt::valid() const
{
	if(!isPresent()) return true;

	if(!initURICheck().isValid(m_impl->value)) {
		LOGIT_DEBUG("Wrong value for NsRevocationUrlExt:" << m_impl->value);
		return false;
	}
	return true;
}

std::vector<std::string>
NsRevocationUrlExt::dump() const
{
	std::vector<std::string> result;
	result.push_back("NsRevocationUrlExt::dump()");

	appendArray(result, ExtensionBase::dump());
	if(!isPresent()) return result;

	result.push_back("URL = " + m_impl->value);

	return result;
}

//    private:
NsRevocationUrlExt::NsRevocationUrlExt()
	: StringExtension(std::string())
{
}


// #################################################################

NsCaRevocationUrlExt::NsCaRevocationUrlExt(const std::string &v)
	: StringExtension(v)
{
	if(!initURICheck().isValid(v)) {
		LOGIT_ERROR("invalid value for NsCaRevocationUrlExt");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid value for NsCaRevocationUrlExt."));
	}
	setPresent(true);
}

NsCaRevocationUrlExt::NsCaRevocationUrlExt(CAConfig* caConfig, Type type)
	: StringExtension(std::string())
{
	// These types are not supported by this object
	if(type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, true), "nsCaRevocationUrl");
	if(p) {
		std::vector<std::string>   sp   = PerlRegEx("\\s*,\\s*")
			.split(caConfig->getValue(type2Section(type, true), "nsCaRevocationUrl"));
		if(0 == str::compareCI(sp[0], "critical")) {
			setCritical(true);
			m_impl->value = sp[1];
		} else {
			m_impl->value = sp[0];
		}
	}
	setPresent(p);
}

NsCaRevocationUrlExt::NsCaRevocationUrlExt(const NsCaRevocationUrlExt &extension)
	: StringExtension(extension)
{}

NsCaRevocationUrlExt::~NsCaRevocationUrlExt()
{}

NsCaRevocationUrlExt&
NsCaRevocationUrlExt::operator=(const NsCaRevocationUrlExt& extension)
{
	if(this == &extension) return *this;

	StringExtension::operator=(extension);

	return *this;
}

void
NsCaRevocationUrlExt::setValue(const std::string &v)
{
	if(!initURICheck().isValid(v)) {
		LOGIT_ERROR("invalid value for NsCaRevocationUrlExt");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid value for NsCaRevocationUrlExt."));
	}
	m_impl->value = v;
	setPresent(true);
}

std::string
NsCaRevocationUrlExt::getValue() const
{
	if(!isPresent()) {
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("NsCaRevocationUrlExt is not present."));
	}
	return m_impl->value;
}

void
NsCaRevocationUrlExt::commit2Config(CA& ca, Type type) const
{
	if(!valid()) {
		LOGIT_ERROR("invalid NsCaRevocationUrlExt object");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid NsCaRevocationUrlExt object."));
	}

	// This extension is not supported by type CRL
	if(type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	if(isPresent()) {
		std::string extString;

		if(isCritical()) extString += "critical,";
		extString += m_impl->value;

		ca.getConfig()->setValue(type2Section(type, true), "nsCaRevocationUrl", extString);
	} else {
		ca.getConfig()->deleteValue(type2Section(type, true), "nsCaRevocationUrl");
	}
}

std::vector<std::string>
NsCaRevocationUrlExt::verify() const
{
	std::vector<std::string> result;

	if(!isPresent()) return result;

	if(!initURICheck().isValid(m_impl->value)) {
		LOGIT_DEBUG("Wrong value for NsCaRevocationUrlExt:" << m_impl->value);
		result.push_back(str::form("Wrong value for NsCaRevocationUrlExt: %s", m_impl->value.c_str()));
	}
	LOGIT_DEBUG_STRINGARRAY("NsCaRevocationUrlExt::verify()", result);
	return result;
}

bool
NsCaRevocationUrlExt::valid() const
{
	if(!isPresent()) return true;

	if(!initURICheck().isValid(m_impl->value)) {
		LOGIT_DEBUG("Wrong value for NsCaRevocationUrlExt:" << m_impl->value);
		return false;
	}
	return true;
}

std::vector<std::string>
NsCaRevocationUrlExt::dump() const
{
	std::vector<std::string> result;
	result.push_back("NsCaRevocationUrlExt::dump()");

	appendArray(result, ExtensionBase::dump());
	if(!isPresent()) return result;

	result.push_back("URL = " + m_impl->value);

	return result;
}

//  private:
NsCaRevocationUrlExt::NsCaRevocationUrlExt()
	: StringExtension(std::string())
{}


// #################################################################

NsRenewalUrlExt::NsRenewalUrlExt(const std::string &v)
	: StringExtension(v)
{
	if(!initURICheck().isValid(v)) {
		LOGIT_ERROR("invalid value for NsRenewalUrlExt");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid value for NsRenewalUrlExt."));
	}
	setPresent(true);
}

NsRenewalUrlExt::NsRenewalUrlExt(CAConfig* caConfig, Type type)
	: StringExtension(std::string())
{
	// These types are not supported by this object
	if(type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, true), "nsRenewalUrl");
	if(p) {
		std::vector<std::string>   sp   = PerlRegEx("\\s*,\\s*")
			.split(caConfig->getValue(type2Section(type, true), "nsRenewalUrl"));
		if(0 == str::compareCI(sp[0], "critical")) {
			setCritical(true);
			m_impl->value = sp[1];
		} else {
			m_impl->value = sp[0];
		}
	}
	setPresent(p);
}

NsRenewalUrlExt::NsRenewalUrlExt(const NsRenewalUrlExt &extension)
	: StringExtension(extension)
{}

NsRenewalUrlExt::~NsRenewalUrlExt()
{}

NsRenewalUrlExt&
NsRenewalUrlExt::operator=(const NsRenewalUrlExt& extension)
{
	if(this == &extension) return *this;

	StringExtension::operator=(extension);

	return *this;
}

void
NsRenewalUrlExt::setValue(const std::string &v)
{
	if(!initURICheck().isValid(v)) {
		LOGIT_ERROR("invalid value for NsRenewalUrlExt");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid value for NsRenewalUrlExt."));
	}
	m_impl->value = v;
	setPresent(true);
}

std::string
NsRenewalUrlExt::getValue() const
{
	if(!isPresent()) {
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("NsRenewalUrlExt is not present."));
	}
	return m_impl->value;
}

void
NsRenewalUrlExt::commit2Config(CA& ca, Type type) const
{
	if(!valid()) {
		LOGIT_ERROR("invalid NsRenewalUrlExt object");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid NsRenewalUrlExt object."));
	}

	// This extension is not supported by type CRL
	if(type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	if(isPresent()) {
		std::string extString;

		if(isCritical()) extString += "critical,";
		extString += m_impl->value;

		ca.getConfig()->setValue(type2Section(type, true), "nsRenewalUrl", extString);
	} else {
		ca.getConfig()->deleteValue(type2Section(type, true), "nsRenewalUrl");
	}
}

std::vector<std::string>
NsRenewalUrlExt::verify() const
{
	std::vector<std::string> result;

	if(!isPresent()) return result;

	if(!initURICheck().isValid(m_impl->value)) {
		LOGIT_DEBUG("Wrong value for NsRenewalUrlExt:" << m_impl->value);
		result.push_back(str::form("Wrong value for NsRenewalUrlExt: %s", m_impl->value.c_str()));
	}
	LOGIT_DEBUG_STRINGARRAY("NsRenewalUrlExt::verify()", result);
	return result;
}

bool
NsRenewalUrlExt::valid() const
{
	if(!isPresent()) return true;

	if(!initURICheck().isValid(m_impl->value)) {
		LOGIT_DEBUG("Wrong value for NsRenewalUrlExt:" << m_impl->value);
		return false;
	}
	return true;
}

std::vector<std::string>
NsRenewalUrlExt::dump() const
{
	std::vector<std::string> result;
	result.push_back("NsRenewalUrlExt::dump()");

	appendArray(result, ExtensionBase::dump());
	if(!isPresent()) return result;

	result.push_back("URL = " + m_impl->value);

	return result;
}

//    private:
NsRenewalUrlExt::NsRenewalUrlExt()
	: StringExtension(std::string())
{}

// #################################################################

NsCaPolicyUrlExt::NsCaPolicyUrlExt(const std::string &v)
	: StringExtension(v)
{
	if(!initURICheck().isValid(v)) {
		LOGIT_ERROR("invalid value for NsCaPolicyUrlExt");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid value for NsCaPolicyUrlExt."));
	}
	setPresent(true);
}

NsCaPolicyUrlExt::NsCaPolicyUrlExt(CAConfig* caConfig, Type type)
	: StringExtension(std::string())
{
	// These types are not supported by this object
	if(type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, true), "nsCaPolicyUrl");
	if(p) {
		std::vector<std::string>   sp   = PerlRegEx("\\s*,\\s*")
			.split(caConfig->getValue(type2Section(type, true), "nsCaPolicyUrl"));
		if(0 == str::compareCI(sp[0], "critical")) {
			setCritical(true);
			m_impl->value = sp[1];
		} else {
			m_impl->value = sp[0];
		}
	}
	setPresent(p);
}

NsCaPolicyUrlExt::NsCaPolicyUrlExt(const NsCaPolicyUrlExt &extension)
	: StringExtension(extension)
{}

NsCaPolicyUrlExt::~NsCaPolicyUrlExt()
{}

NsCaPolicyUrlExt&
NsCaPolicyUrlExt::operator=(const NsCaPolicyUrlExt& extension)
{
	if(this == &extension) return *this;

	StringExtension::operator=(extension);

	return *this;
}

void
NsCaPolicyUrlExt::setValue(const std::string &v)
{
	if(!initURICheck().isValid(v)) {
		LOGIT_ERROR("invalid value for NsCaPolicyUrlExt");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid value for NsCaPolicyUrlExt."));
	}
	m_impl->value = v;
	setPresent(true);
}

std::string
NsCaPolicyUrlExt::getValue() const
{
	if(!isPresent()) {
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("NsCaPolicyUrlExt is not present."));
	}
	return m_impl->value;
}

void
NsCaPolicyUrlExt::commit2Config(CA& ca, Type type) const
{
	if(!valid()) {
		LOGIT_ERROR("invalid NsCaPolicyUrlExt object");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid NsCaPolicyUrlExt object."));
	}

	// This extension is not supported by type CRL
	if(type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	if(isPresent()) {
		std::string extString;

		if(isCritical()) extString += "critical,";
		extString += m_impl->value;

		ca.getConfig()->setValue(type2Section(type, true), "nsCaPolicyUrl", extString);
	} else {
		ca.getConfig()->deleteValue(type2Section(type, true), "nsCaPolicyUrl");
	}
}

std::vector<std::string>
NsCaPolicyUrlExt::verify() const
{
	std::vector<std::string> result;

	if(!isPresent()) return result;

	if(!initURICheck().isValid(m_impl->value)) {
		LOGIT_DEBUG("Wrong value for NsCaPolicyUrlExt:" << m_impl->value);
		result.push_back(str::form("Wrong value for NsCaPolicyUrlExt: %s", m_impl->value.c_str()));
	}
	LOGIT_DEBUG_STRINGARRAY("NsCaPolicyUrlExt::verify()", result);
	return result;
}

bool
NsCaPolicyUrlExt::valid() const
{
	if(!isPresent()) return true;

	if(!initURICheck().isValid(m_impl->value)) {
		LOGIT_DEBUG("Wrong value for NsCaPolicyUrlExt:" << m_impl->value);
		return false;
	}
	return true;
}

std::vector<std::string>
NsCaPolicyUrlExt::dump() const
{
	std::vector<std::string> result;
	result.push_back("NsCaPolicyUrlExt::dump()");

	appendArray(result, ExtensionBase::dump());
	if(!isPresent()) return result;

	result.push_back("URL = " + m_impl->value);

	return result;
}

//    private:
NsCaPolicyUrlExt::NsCaPolicyUrlExt()
	: StringExtension(std::string())
{}


// #################################################################

NsSslServerNameExt::NsSslServerNameExt(const std::string &v)
	: StringExtension(v)
{
	setPresent(true);
}

NsSslServerNameExt::NsSslServerNameExt(CAConfig* caConfig, Type type)
	: StringExtension(std::string())
{
	// These types are not supported by this object
	if(type == E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Invalid type: %1."), type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, true), "nsSslServerName");
	if(p) {
		std::vector<std::string>   sp   = PerlRegEx("\\s*,\\s*")
			.split(caConfig->getValue(type2Section(type, true), "nsSslServerName"));
		if(0 == str::compareCI(sp[0], "critical")) {
			setCritical(true);
			m_impl->value = sp[1];
		} else {
			m_impl->value = sp[0];
		}
	}
	setPresent(p);
}

NsSslServerNameExt::NsSslServerNameExt(const NsSslServerNameExt &extension)
	: StringExtension(extension)
{}

NsSslServerNameExt::~NsSslServerNameExt()
{}

NsSslServerNameExt&
NsSslServerNameExt::operator=(const NsSslServerNameExt& extension)
{
	if(this == &extension) return *this;

	StringExtension::operator=(extension);

	return *this;
}

void
NsSslServerNameExt::setValue(const std::string &v)
{
	m_impl->value = v;
	setPresent(true);
}

std::string
NsSslServerNameExt::getValue() const
{
	if(!isPresent()) {
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("NsSslServerNameExt is not present."));
	}
	return m_impl->value;
}

void
NsSslServerNameExt::commit2Config(CA& ca, Type type) const
{
	if(!valid()) {
		LOGIT_ERROR("invalid NsSslServerNameExt object");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid NsSslServerNameExt object."));
	}

	// This extension is not supported by type CRL
	if(type == E_CRL) {
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	if(isPresent()) {
		std::string extString;

		if(isCritical()) extString += "critical,";
		extString += m_impl->value;

		ca.getConfig()->setValue(type2Section(type, true), "nsSslServerName", extString);
	} else {
		ca.getConfig()->deleteValue(type2Section(type, true), "nsSslServerName");
	}
}

std::vector<std::string>
NsSslServerNameExt::verify() const
{
	return std::vector<std::string>();
}

bool
NsSslServerNameExt::valid() const
{
	return true;
}

std::vector<std::string>
NsSslServerNameExt::dump() const
{
	std::vector<std::string> result;
	result.push_back("NsSslServerNameExt::dump()");

	appendArray(result, ExtensionBase::dump());
	if(!isPresent()) return result;

	result.push_back("SSL server name = " + m_impl->value);

	return result;
}

//    private:

NsSslServerNameExt::NsSslServerNameExt()
	: StringExtension(std::string())
{}

// #################################################################

NsCommentExt::NsCommentExt(const std::string &v)
	: StringExtension(v)
{
	setPresent(true);
}

NsCommentExt::NsCommentExt(CAConfig* caConfig, Type type)
	: StringExtension(std::string())
{
	// These types are not supported by this object
	if(type == E_CRL) {
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, true), "nsComment");
	if(p) {
		std::vector<std::string>   sp   = PerlRegEx("\\s*,\\s*")
			.split(caConfig->getValue(type2Section(type, true), "nsComment"));
		if(0 == str::compareCI(sp[0], "critical")) {
			setCritical(true);
			m_impl->value = sp[1];
		} else {
			m_impl->value = sp[0];
		}
	}
	setPresent(p);
}

NsCommentExt::NsCommentExt(const NsCommentExt &extension)
	: StringExtension(extension)
{}

NsCommentExt::~NsCommentExt()
{}

NsCommentExt&
NsCommentExt::operator=(const NsCommentExt& extension)
{
	if(this == &extension) return *this;

	StringExtension::operator=(extension);

	return *this;
}

void
NsCommentExt::setValue(const std::string &v)
{
	m_impl->value = v;
	setPresent(true);
}

std::string
NsCommentExt::getValue() const
{
	if(!isPresent()) {
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("NsCommentExt is not present."));
	}
	return m_impl->value;
}

void
NsCommentExt::commit2Config(CA& ca, Type type) const
{
	if(!valid()) {
		LOGIT_ERROR("invalid NsCommentExt object");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid NsCommentExt object."));
	}

	// This extension is not supported by type CRL
	if(type == E_CRL) {
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	if(isPresent()) {
		std::string extString;

		if(isCritical()) extString += "critical,";
		extString += m_impl->value;

		ca.getConfig()->setValue(type2Section(type, true), "nsComment", extString);
	} else {
		ca.getConfig()->deleteValue(type2Section(type, true), "nsComment");
	}
}

std::vector<std::string>
NsCommentExt::verify() const
{
	return std::vector<std::string>();
}

bool
	NsCommentExt::valid() const
{
	return true;
}

std::vector<std::string>
NsCommentExt::dump() const
{
	std::vector<std::string> result;
	result.push_back("NsCommentExt::dump()");

	appendArray(result, ExtensionBase::dump());
	if(!isPresent()) return result;

	result.push_back("NS Comment = " + m_impl->value);

	return result;
}

//    private:
NsCommentExt::NsCommentExt()
	: StringExtension(std::string())
{}

}
