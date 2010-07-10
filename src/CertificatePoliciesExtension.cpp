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

  File:       CertificatePoliciesExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  <limal/ca-mgm/CertificatePoliciesExtension.hpp>
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>



#include  "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;
using namespace blocxx;

class UserNoticeImpl
{
public:
	UserNoticeImpl()
		: explicitText("")
		, organization("")
		, noticeNumbers(std::list<int32_t>())
	{}

	UserNoticeImpl(const UserNoticeImpl& impl)
		: explicitText(impl.explicitText)
		, organization(impl.organization)
		, noticeNumbers(impl.noticeNumbers)
	{}

	~UserNoticeImpl() {}

	UserNoticeImpl* clone() const
	{
		return new UserNoticeImpl(*this);
	}

	std::string              explicitText;      // max 200 characters

	// The organization and noticeNumbers options
	// (if included) must BOTH be present.

	std::string                      organization;      // max 200 characters
	std::list<int32_t> noticeNumbers;

};

class CertificatePolicyImpl
{
public:

	CertificatePolicyImpl()
		: policyIdentifier(std::string())
		, cpsURI(StringList())
		, noticeList(std::list<UserNotice>())
	{}

	CertificatePolicyImpl(const std::string &policyIdentifier)
		: policyIdentifier(policyIdentifier)
		, cpsURI(StringList())
		, noticeList(std::list<UserNotice>())
	{}

	CertificatePolicyImpl(const CertificatePolicyImpl& impl)
		: policyIdentifier(impl.policyIdentifier)
		, cpsURI(impl.cpsURI)
		, noticeList(impl.noticeList)
	{}

	~CertificatePolicyImpl() {}

	CertificatePolicyImpl* clone() const
	{
		return new CertificatePolicyImpl(*this);
	}

	std::string                   policyIdentifier;  // required
	StringList               cpsURI;            // Certification Practice Statement

	std::list<UserNotice> noticeList;
};

class CertificatePoliciesExtImpl
{
public:
	CertificatePoliciesExtImpl()
		: ia5org(false),
		policies(std::list<CertificatePolicy>())
	{}

	CertificatePoliciesExtImpl(const std::list<CertificatePolicy>& policies)
		: ia5org(false),
		policies(policies)
	{}

	CertificatePoliciesExtImpl(const CertificatePoliciesExtImpl& impl)
		: ia5org(impl.ia5org)
		, policies(impl.policies)
	{}

	~CertificatePoliciesExtImpl() {}

	CertificatePoliciesExtImpl* clone() const
	{
		return new CertificatePoliciesExtImpl(*this);
	}

	bool ia5org;
	std::list<CertificatePolicy> policies;

};

UserNotice::UserNotice()
	: m_impl(new UserNoticeImpl())
{}

UserNotice::UserNotice(const UserNotice& notice)
	: m_impl(notice.m_impl)
{}

UserNotice::~UserNotice()
{}

UserNotice&
UserNotice::operator=(const UserNotice& notice)
{
	if(this == &notice) return *this;

	m_impl = notice.m_impl;

	return *this;
}

void
UserNotice::initWithSection(CAConfig* caConfig, Type type, const std::string& sectionName)
{
    // These types are not supported by this object
	if(type == E_CRL        || type == E_Client_Req ||
	   type == E_Server_Req || type == E_CA_Req      )
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	bool p = caConfig->exists(sectionName, "explicitText");
	if(p)
	{
		m_impl->explicitText = caConfig->getValue(sectionName, "explicitText");
	}
	else
	{
		LOGIT_DEBUG("no explicite Text in " << sectionName);
	}

	p = caConfig->exists(sectionName, "organization");
	if(p)
	{
		m_impl->organization = caConfig->getValue(sectionName, "organization");
	}
	else
	{
		LOGIT_DEBUG("no Organization in " << sectionName);
	}

	p = caConfig->exists(sectionName, "noticeNumbers");
	if(p)
	{
		std::vector<std::string> a = PerlRegEx(",").
			split(caConfig->getValue(sectionName, "noticeNumbers"));
		std::vector<std::string>::const_iterator it = a.begin();
		for(; it != a.end(); ++it)
		{
			m_impl->noticeNumbers.push_back(str::strtonum<uint32_t>(*it));
		}
	}
	else
	{
		LOGIT_DEBUG("no Notice Numbers in " << sectionName);
	}
}

void
UserNotice::setExplicitText(const std::string& text)
{
	if(text.length() > 200)
	{
		LOGIT_ERROR("The text is too long.");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("The text is too long."));
	}

	m_impl->explicitText = text;
}

std::string
UserNotice::getExplicitText() const
{
	return m_impl->explicitText;
}

void
UserNotice::setOrganizationNotice(const std::string& org,
                                  const std::list<int32_t>& numbers)
{
	m_impl->organization  = org;
	m_impl->noticeNumbers = numbers;
}

std::string
UserNotice::getOrganization() const
{
	return m_impl->organization;
}

std::list<int32_t>
UserNotice::getNoticeNumbers() const
{
	return m_impl->noticeNumbers;
}

std::string
UserNotice::commit2Config(CA& ca, Type type, uint32_t num) const
{
	if(!valid())
	{
		LOGIT_ERROR("invalid UserNotice object");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid UserNotice object."));
	}

    // These types are not supported by this object
	if(type == E_CRL        || type == E_Client_Req ||
	   type == E_Server_Req || type == E_CA_Req      )
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

    // we need a User Notice section
	std::string sectionName = std::string("notice")+type2Section(type, true)+str::numstring(num);

	if(!m_impl->explicitText.empty())
	{
		ca.getConfig()->setValue(sectionName, "explicitText", m_impl->explicitText);
	}

	if(!m_impl->organization.empty())
	{
		ca.getConfig()->setValue(sectionName, "organization", m_impl->organization);

		std::string numbers;
		std::list<int32_t>::const_iterator it = m_impl->noticeNumbers.begin();
		for(;it != m_impl->noticeNumbers.end(); ++it)
		{
			numbers += str::numstring(*it)+",";
		}
		ca.getConfig()->setValue(sectionName, "noticeNumbers",
		                         numbers.erase(numbers.length()-1));
	}
	return ("@"+sectionName);
}

bool
UserNotice::valid() const
{
	if(m_impl->explicitText.length() > 200)
	{
		LOGIT_DEBUG("explicitText to long");
		return false;
	}

	if((m_impl->organization.empty() && !m_impl->noticeNumbers.empty()) ||
	   (!m_impl->organization.empty() && m_impl->noticeNumbers.empty()))
	{
		LOGIT_DEBUG("organization and noticeNumbers must both present or absent");
		return false;
	}
	return true;
}

std::vector<std::string>
UserNotice::verify() const
{
	std::vector<std::string> result;

	if(m_impl->explicitText.length() > 200)
	{
		result.push_back("explicitText to long");
	}

	if((m_impl->organization.empty() && !m_impl->noticeNumbers.empty()) ||
	   (!m_impl->organization.empty() && m_impl->noticeNumbers.empty()))
	{
		result.push_back("organization and noticeNumbers must both present or absent");
	}
	LOGIT_DEBUG_STRINGARRAY("UserNotice::verify()", result);
	return result;
}

std::vector<std::string>
UserNotice::dump() const
{
	std::vector<std::string> result;
	result.push_back("UserNotice::dump()");

	result.push_back("explicitText = "+ m_impl->explicitText);
	result.push_back("organization = " + m_impl->organization);

	std::string n;
	std::list< int32_t >::const_iterator it = m_impl->noticeNumbers.begin();
	for(; it != m_impl->noticeNumbers.end(); ++it)
	{
		n += str::numstring(*it) + " ";
	}
	result.push_back("noticeNumbers = " + n);

	return result;
}

bool
operator==(const UserNotice &l, const UserNotice &r)
{
	if(l.getExplicitText()  == r.getExplicitText() &&
	   l.getOrganization()  == r.getOrganization() &&
	   l.getNoticeNumbers() == r.getNoticeNumbers())
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool
operator<(const UserNotice &l, const UserNotice &r)
{
    // this is only to make a List happy

	if(l.getExplicitText()  < r.getExplicitText() ||
	   l.getOrganization()  < r.getOrganization() ||
	   l.getNoticeNumbers() < r.getNoticeNumbers())
	{
		return true;
	}
	else
	{
		return false;
	}
}


// ###########################################################################

CertificatePolicy::CertificatePolicy()
	: m_impl(new CertificatePolicyImpl())
{}

CertificatePolicy::CertificatePolicy(const std::string& policyIdentifier)
	: m_impl(new CertificatePolicyImpl(policyIdentifier))
{
	if(!initOIDCheck().isValid(policyIdentifier))
	{
		LOGIT_ERROR("invalid value for policyIdentifier" << policyIdentifier);
		CA_MGM_THROW(ca_mgm::ValueException ,
		             // %s is the wrong string for policyIdentifier
		             str::form(__("Invalid value for policyIdentifier: %s."), policyIdentifier.c_str()).c_str());
	}
}

CertificatePolicy::CertificatePolicy(const CertificatePolicy& policy)
	: m_impl(policy.m_impl)
{}

CertificatePolicy::~CertificatePolicy()
{}

CertificatePolicy&
CertificatePolicy::operator=(const CertificatePolicy& policy)
{
	if(this == &policy) return *this;

	m_impl = policy.m_impl;

	return *this;
}

void
CertificatePolicy::initWithSection(CAConfig* caConfig, Type type, const std::string& sectionName)
{
    // These types are not supported by this object
	if(type == E_CRL        || type == E_Client_Req ||
	   type == E_Server_Req || type == E_CA_Req      )
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	bool p = caConfig->exists(sectionName, "policyIdentifier");
	if(p)
	{
		m_impl->policyIdentifier = caConfig->getValue(sectionName, "policyIdentifier");
	}

	StringList kl = caConfig->getKeylist(sectionName);
	StringList::const_iterator it = kl.begin();
	for(; it != kl.end(); ++it)
	{
		if(str::startsWith(*it,"CPS"))
		{
			m_impl->cpsURI.push_back(caConfig->getValue(sectionName, *it));
		}
		else if(str::startsWith(*it, "userNotice"))
		{
			std::string uns = caConfig->getValue(sectionName, *it);
			UserNotice un = UserNotice();
			un.initWithSection(caConfig, type, uns.substr(1));
			m_impl->noticeList.push_back(un);
		}
	}
}

void
CertificatePolicy::setPolicyIdentifier(const std::string& policyIdentifier)
{
	if(!initOIDCheck().isValid(policyIdentifier))
	{
		LOGIT_ERROR("invalid value for policyIdentifier" << policyIdentifier);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Invalid value for policyIdentifier: %s."), policyIdentifier.c_str()).c_str());
	}

	m_impl->policyIdentifier = policyIdentifier;
}

std::string
CertificatePolicy::getPolicyIdentifier() const
{
	return m_impl->policyIdentifier;
}

void
CertificatePolicy::setCpsURI(const StringList& cpsURI)
{
	std::vector<std::string> r = checkCpsURIs(cpsURI);
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		CA_MGM_THROW(ca_mgm::ValueException, r[0].c_str());
	}
	m_impl->cpsURI = cpsURI;
}

StringList
CertificatePolicy::getCpsURI() const
{
	return m_impl->cpsURI;
}

void
CertificatePolicy::setUserNoticeList(const std::list<UserNotice>& list)
{
	std::vector<std::string> r = checkNoticeList(list);
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		CA_MGM_THROW(ca_mgm::ValueException, r[0].c_str());
	}
	m_impl->noticeList = list;
}

std::list<UserNotice>
CertificatePolicy::getUserNoticeList() const
{
	return m_impl->noticeList;
}

std::string
CertificatePolicy::commit2Config(CA& ca, Type type, uint32_t num) const
{
	if(!valid())
	{
		LOGIT_ERROR("invalid CertificatePolicy object");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid CertificatePolicy object."));
	}

    // These types are not supported by this object
	if(type == E_CRL        || type == E_Client_Req ||
	   type == E_Server_Req || type == E_CA_Req      )
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	if(m_impl->cpsURI.empty()) {
        // no practice statement; return directly the policyIdentifier
		return m_impl->policyIdentifier;
	}
    // we need a policy section
	std::string sectionName = std::string("polsec")+type2Section(type, true)+str::numstring(num);

	ca.getConfig()->setValue(sectionName, "policyIdentifier", m_impl->policyIdentifier);

	StringList::const_iterator it = m_impl->cpsURI.begin();
	for(uint32_t i = 1;it != m_impl->cpsURI.end(); ++it, ++i)
	{
		ca.getConfig()->setValue(sectionName, "CPS."+str::numstring(i),(*it));
	}

	std::list<UserNotice>::const_iterator nit = m_impl->noticeList.begin();
	for(uint32_t j = 1;nit != m_impl->noticeList.end(); ++nit, ++j)
	{
		std::string n = (*nit).commit2Config(ca, type, j);
		ca.getConfig()->setValue(sectionName, "userNotice."+str::numstring(j),n);
	}

	return ("@"+sectionName);
}

bool
CertificatePolicy::valid() const
{
	if(m_impl->policyIdentifier.empty() ||
	   !initOIDCheck().isValid(m_impl->policyIdentifier))
	{
		LOGIT_DEBUG("invalid value for policyIdentifier:" << m_impl->policyIdentifier);
		return false;
	}

	std::vector<std::string> r = checkCpsURIs(m_impl->cpsURI);
	if(!r.empty())
	{
		LOGIT_DEBUG(r[0]);
		return false;
	}

	r = checkNoticeList(m_impl->noticeList);
	if(!r.empty())
	{
		LOGIT_DEBUG(r[0]);
		return false;
	}
	return true;
}

std::vector<std::string>
CertificatePolicy::verify() const
{
	std::vector<std::string> result;

	ValueCheck oidCheck = initOIDCheck();

	if(m_impl->policyIdentifier.empty() ||
	   !oidCheck.isValid(m_impl->policyIdentifier))
	{
		result.push_back(str::form("invalid value for policyIdentifier: %s",
		                     m_impl->policyIdentifier.c_str()));
	}

	appendArray(result, checkCpsURIs(m_impl->cpsURI));

	appendArray(result, checkNoticeList(m_impl->noticeList));

	LOGIT_DEBUG_STRINGARRAY("CertificatePolicy::verify()", result);
	return result;
}

std::vector<std::string>
CertificatePolicy::dump() const
{
	std::vector<std::string> result;
	result.push_back("CertificatePolicy::dump()");

	result.push_back("policy Identifier = " + m_impl->policyIdentifier);

	StringList::const_iterator it1 = m_impl->cpsURI.begin();
	for(; it1 != m_impl->cpsURI.end(); ++it1)
	{
		result.push_back("CPS = " + (*it1));
	}

	std::list< UserNotice >::const_iterator it2 = m_impl->noticeList.begin();
	for(; it2 != m_impl->noticeList.end(); ++it2)
	{
		appendArray(result, (*it2).dump());
	}
	return result;
}

bool
operator==(const CertificatePolicy &l, const CertificatePolicy &r)
{
	if(l.getPolicyIdentifier() == r.getPolicyIdentifier() &&
	   l.getCpsURI()           == r.getCpsURI()           &&
	   l.getUserNoticeList()   == r.getUserNoticeList() )
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool
operator<(const CertificatePolicy &l, const CertificatePolicy &r)
{
    // this is only to make a List happy

	if(l.getPolicyIdentifier() < r.getPolicyIdentifier() ||
	   l.getCpsURI()           < r.getCpsURI()           ||
	   l.getUserNoticeList()   < r.getUserNoticeList() )
	{
		return true;
	}
	else
	{
		return false;
	}
}

std::vector<std::string>
CertificatePolicy::checkCpsURIs(const StringList& cpsURIs) const
{
	std::vector<std::string> result;
	ValueCheck  uriCheck = initURICheck();

	StringList::const_iterator it = cpsURIs.begin();
	for(;it != cpsURIs.end(); it++)
	{
		if(!uriCheck.isValid(*it))
		{
			result.push_back(str::form("invalid URI: %s", (*it).c_str()));
		}
	}
	return result;
}

std::vector<std::string>
CertificatePolicy::checkNoticeList(const std::list<UserNotice>& list) const
{
	std::vector<std::string> result;
	std::list<UserNotice>::const_iterator it = list.begin();
	for(;it != list.end(); it++)
	{
		appendArray(result, (*it).verify());
	}
	return result;
}


// ###################################################################################

CertificatePoliciesExt::CertificatePoliciesExt()
	: ExtensionBase()
	, m_impl(new CertificatePoliciesExtImpl())
{}

CertificatePoliciesExt::CertificatePoliciesExt(const std::list<CertificatePolicy>& policies)
	: ExtensionBase()
	, m_impl(new CertificatePoliciesExtImpl(policies))
{
	std::vector<std::string> r = checkPolicies(policies);
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		CA_MGM_THROW(ca_mgm::ValueException, r[0].c_str());
	}
	setPresent(true);
}

CertificatePoliciesExt::CertificatePoliciesExt(CAConfig* caConfig, Type type)
	: ExtensionBase()
	, m_impl(new CertificatePoliciesExtImpl())
{
    // These types are not supported by this object
	if(type == E_CRL        || type == E_Client_Req ||
	   type == E_Server_Req || type == E_CA_Req      )
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	bool p = caConfig->exists(type2Section(type, true), "certificatePolicies");
	if(p)
	{
		ValueCheck    check = initOIDCheck();
		std::vector<std::string>   sp    = PerlRegEx("\\s*,\\s*")
			.split(caConfig->getValue(type2Section(type, true), "certificatePolicies"));

		if(0 == str::compareCI(sp[0], "critical"))
		{
			setCritical(true);
			sp.erase(sp.begin());
		}

		std::vector<std::string>::const_iterator it = sp.begin();
		for(; it != sp.end(); ++it)
		{
			if(0 == str::compareCI(*it, "ia5org"))
			{
				m_impl->ia5org = true;
			}
			else if(check.isValid(*it))
			{
				m_impl->policies.push_back(CertificatePolicy(*it));
			}
			else if(str::startsWith(*it, "@"))
			{
				CertificatePolicy cp = CertificatePolicy();
				cp.initWithSection(caConfig, type, (*it).substr(1));
				m_impl->policies.push_back(cp);
			}
		}
	}
	setPresent(p);
}

CertificatePoliciesExt::CertificatePoliciesExt(const CertificatePoliciesExt& extension)
	: ExtensionBase(extension),
	m_impl(extension.m_impl)
{}

CertificatePoliciesExt::~CertificatePoliciesExt()
{}

CertificatePoliciesExt&
CertificatePoliciesExt::operator=(const CertificatePoliciesExt& extension)
{
	if(this == &extension) return *this;

	ExtensionBase::operator=(extension);

	m_impl = extension.m_impl;

	return *this;
}

void
CertificatePoliciesExt::enableIA5org(bool ia5org)
{
	m_impl->ia5org = ia5org;
}

bool
CertificatePoliciesExt::isIA5orgEnabled() const
{
	if(!isPresent())
	{
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("CertificatePoliciesExt is not present."));
	}
	return m_impl->ia5org;
}

void
CertificatePoliciesExt::setPolicies(const std::list<CertificatePolicy>& policies)
{
	std::vector<std::string> r = checkPolicies(policies);
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		CA_MGM_THROW(ca_mgm::ValueException, r[0].c_str());
	}
	m_impl->policies = policies;

	setPresent(true);
}

std::list<CertificatePolicy>
CertificatePoliciesExt::getPolicies() const
{
	if(!isPresent())
	{
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("CertificatePoliciesExt is not present."));
	}
	return m_impl->policies;
}


void
CertificatePoliciesExt::commit2Config(CA& ca, Type type) const
{
	if(!valid())
	{
		LOGIT_ERROR("invalid CertificatePoliciesExt object");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid CertificatePoliciesExt object."));
	}

    // These types are not supported by this object
	if(type == E_CRL        || type == E_Client_Req ||
	   type == E_Server_Req || type == E_CA_Req      )
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	if(isPresent())
	{
		std::string extString;

		if(isCritical()) extString += "critical,";

		if(m_impl->ia5org) extString += "ia5org,";

		std::list<CertificatePolicy>::const_iterator it = m_impl->policies.begin();
		for(uint32_t i = 0;it != m_impl->policies.end(); ++it, ++i)
		{
			extString += (*it).commit2Config(ca, type, i) + ",";
		}

		ca.getConfig()->setValue(type2Section(type, true), "certificatePolicies",
		                         extString.erase(extString.length()-1));
	}
	else
	{
		ca.getConfig()->deleteValue(type2Section(type, true), "certificatePolicies");
	}
}

bool
CertificatePoliciesExt::valid() const
{
	if(!isPresent()) return true;

	if(m_impl->policies.empty())
	{
		LOGIT_DEBUG("No policy set");
		return false;
	}
	std::vector<std::string> r = checkPolicies(m_impl->policies);
	if(!r.empty())
	{
		LOGIT_DEBUG(r[0]);
		return false;
	}
	return true;
}

std::vector<std::string>
CertificatePoliciesExt::verify() const
{
	std::vector<std::string> result;

	if(!isPresent()) return result;

	if(m_impl->policies.empty())
	{
		result.push_back("No policy set");
	}
	appendArray(result, checkPolicies(m_impl->policies));

	LOGIT_DEBUG_STRINGARRAY("CertificatePoliciesExt::verify()", result);

	return result;
}

std::vector<std::string>
CertificatePoliciesExt::dump() const
{
	std::vector<std::string> result;
	result.push_back("CertificatePoliciesExt::dump()");

	appendArray(result, ExtensionBase::dump());
	if(!isPresent()) return result;

	result.push_back("ia5org = " + str::toString(m_impl->ia5org));
	std::list< CertificatePolicy >::const_iterator it = m_impl->policies.begin();
	for(; it != m_impl->policies.end(); ++it)
	{
		appendArray(result, (*it).dump());
	}

	return result;
}


std::vector<std::string>
CertificatePoliciesExt::checkPolicies(const std::list<CertificatePolicy>& pl) const
{
	std::vector<std::string> result;
	std::list<CertificatePolicy>::const_iterator it = pl.begin();
	for(;it != pl.end(); it++)
	{
		appendArray(result, (*it).verify());
	}
	return result;
}

}
