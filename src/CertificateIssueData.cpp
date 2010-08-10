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

  File:       CertificateIssueData.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/CA.hpp>
#include  <limal/ca-mgm/CertificateIssueData.hpp>
#include  <limal/Exception.hpp>

#include  <limal/Date.hpp>


#include  "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;

class CertificateIssueDataImpl
{
public:
	CertificateIssueDataImpl()
		: notBefore(0)
		, notAfter(0)
		, messageDigest(E_SHA1)
		, extensions(X509v3CertificateIssueExts())
	{}

	CertificateIssueDataImpl(const CertificateIssueDataImpl& impl)
		: notBefore(impl.notBefore)
		, notAfter(impl.notAfter)
		, messageDigest(impl.messageDigest)
		, extensions(impl.extensions)
	{}

	~CertificateIssueDataImpl() {}

	CertificateIssueDataImpl* clone() const
	{
		return new CertificateIssueDataImpl(*this);
	}

	time_t                     notBefore;
	time_t                     notAfter;

	// KeyAlg        pubkeyAlgorithm; // at the beginning we only support rsa

	MD                         messageDigest; // parameter default_md

	X509v3CertificateIssueExts extensions;

};


CertificateIssueData::CertificateIssueData()
	: m_impl(new CertificateIssueDataImpl())
{}

CertificateIssueData::CertificateIssueData(CAConfig* caConfig, Type type)
	: m_impl(new CertificateIssueDataImpl())
{
	m_impl->notBefore = Date::now();

	uint32_t days = str::strtonum<uint32_t>(caConfig->getValue(type2Section(type, false), "default_days"));
	Date dt = Date(getStartDate());
	dt += (days*24*60*60);
	m_impl->notAfter    = dt;

	std::string md = caConfig->getValue(type2Section(type, false), "default_md");
	if(0 == str::compareCI(md, "sha1"))
	{
		setMessageDigest( E_SHA1 );
	}
	else if(0 == str::compareCI(md, "md5"))
	{
		setMessageDigest( E_MD5 );
	}
	else if(0 == str::compareCI(md, "mdc2"))
	{
		setMessageDigest( E_MDC2 );
	}
	else
	{
		LOGIT_INFO("unsupported message digest: " << md);
		LOGIT_INFO("select default sha1.");
		setMessageDigest( E_SHA1 );
	}

	setExtensions( X509v3CertificateIssueExts(caConfig, type));
}

CertificateIssueData::CertificateIssueData(const CertificateIssueData& data)
	: m_impl(data.m_impl)
{}

CertificateIssueData::~CertificateIssueData()
{}

CertificateIssueData&
CertificateIssueData::operator=(const CertificateIssueData& data)
{
	if(this == &data) return *this;

	m_impl = data.m_impl;

	return *this;
}

void
CertificateIssueData::setCertifyPeriode(time_t start, time_t end)
{
	m_impl->notBefore = start;
	m_impl->notAfter  = end;
}

time_t
CertificateIssueData::getStartDate() const
{
	return m_impl->notBefore;
}

time_t
	CertificateIssueData::getEndDate() const
{
	return m_impl->notAfter;
}

std::string
CertificateIssueData::getStartDateAsString() const
{
	Date dt(getStartDate());
	std::string time(dt.form("%y%m%d%H%M%S", true) + "Z");

	return time;
}

std::string
CertificateIssueData::getEndDateAsString() const
{
	Date dt(getEndDate());
	std::string time(dt.form("%y%m%d%H%M%S", true) + "Z");

	return time;
}

void
CertificateIssueData::setMessageDigest(MD md)
{
	m_impl->messageDigest = md;
}

MD
CertificateIssueData::getMessageDigest() const
{
	return m_impl->messageDigest;
}

void
CertificateIssueData::setExtensions(const X509v3CertificateIssueExts& ext)
{
	std::vector<std::string> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		CA_MGM_THROW(ca_mgm::ValueException, r[0].c_str());
	}
	m_impl->extensions = ext;
}

X509v3CertificateIssueExts
	CertificateIssueData::getExtensions() const
{
	return m_impl->extensions;
}

X509v3CertificateIssueExts&
CertificateIssueData::extensions()
{
	return m_impl->extensions;
}

void
CertificateIssueData::commit2Config(CA& ca, Type type) const
{
	if(!valid())
	{
		LOGIT_ERROR("invalid CertificateIssueData object");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid CertificateIssueData object."));
	}
	// These types are not supported by this object
	if(type == E_CRL        || type == E_Client_Req ||
	   type == E_Server_Req || type == E_CA_Req)
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %d."), type).c_str());
	}
	uint32_t t = (uint32_t)((getEndDate() - getStartDate())/(60*60*24));

	ca.getConfig()->setValue(type2Section(type, false), "default_days", str::numstring(t));

	std::string md("sha1");
	switch(getMessageDigest())
	{
	case E_SHA1:
		md = "sha1";
		break;
	case E_MD5:
		md = "md5";
		break;
	case E_MDC2:
		md = "mdc2";
		break;
	}
	ca.getConfig()->setValue(type2Section(type, false), "default_md", md);

	m_impl->extensions.commit2Config(ca, type);
}

bool
CertificateIssueData::valid() const
{
	if(getStartDate() == 0)
	{
		LOGIT_DEBUG("invalid notBefore:" << getStartDate());
		return false;
	}
	if(getEndDate() <= getStartDate())
	{
		LOGIT_DEBUG("invalid notAfter:" << getEndDate() <<
		            " notBefore = "     << getStartDate());
		return false;
	}

	if(!m_impl->extensions.valid()) return false;

	return true;
}

std::vector<std::string>
CertificateIssueData::verify() const
{
	std::vector<std::string> result;

	if(getStartDate() == 0)
	{
		result.push_back(str::form("invalid notBefore: %ld", getStartDate()));
	}
	if(getEndDate() <= getStartDate())
	{
		result.push_back(str::form("invalid notAfter %ld <= notBefore %ld",
		                     getEndDate(), getStartDate()));
	}

	appendArray(result, m_impl->extensions.verify());

	LOGIT_DEBUG_STRINGARRAY("CertificateIssueData::verify()", result);

	return result;
}

std::vector<std::string>
CertificateIssueData::dump() const
{
	std::vector<std::string> result;
	result.push_back("CertificateIssueData::dump()");

	result.push_back("!CHANGING DATA! notBefore = " + str::numstring(getStartDate()));
	result.push_back("!CHANGING DATA! notAfter = " + str::numstring(getEndDate()));
	result.push_back("notAfter - notBefore (in days)= " +
	              str::numstring((getEndDate() - getStartDate())/86400));
	result.push_back("MessageDigest = " + str::numstring(getMessageDigest()));
	appendArray(result, getExtensions().dump());

	return result;
}

}
