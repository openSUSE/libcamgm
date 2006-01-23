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
#include  <blocxx/Format.hpp>
#include  <blocxx/DateTime.hpp>
#include  <blocxx/COWIntrusiveCountableBase.hpp>

#include  "Utils.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;

class CertificateIssueDataImpl : public blocxx::COWIntrusiveCountableBase
{
	public:
	CertificateIssueDataImpl()
		: notBefore(0)
		, notAfter(0)
		, messageDigest(E_SHA1)
		, extensions(X509v3CertificateIssueExts())
	{}
		
	CertificateIssueDataImpl(const CertificateIssueDataImpl& impl)
		: COWIntrusiveCountableBase(impl)
		, notBefore(impl.notBefore)
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
	m_impl->notBefore = DateTime::getCurrent().get();

	UInt32 days = caConfig->getValue(type2Section(type, false), "default_days").toUInt32();
	DateTime dt = DateTime(getStartDate());
	dt.addDays(days);
	m_impl->notAfter    = dt.get();

	String md = caConfig->getValue(type2Section(type, false), "default_md");
	if(md.equalsIgnoreCase("sha1"))
	{
		setMessageDigest( E_SHA1 );
	}
	else if(md.equalsIgnoreCase("md5"))
	{
		setMessageDigest( E_MD5 );
	}
	else if(md.equalsIgnoreCase("mdc2"))
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

blocxx::String
CertificateIssueData::getStartDateAsString() const
{
	DateTime dt(getStartDate());
	String time = dt.toString("%y%m%d%H%M%S", DateTime::E_UTC_TIME) + "Z";
    
	return time;
}

blocxx::String
CertificateIssueData::getEndDateAsString() const
{
	DateTime dt(getEndDate());
	String time = dt.toString("%y%m%d%H%M%S", DateTime::E_UTC_TIME) + "Z";
    
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
	StringArray r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(limal::ValueException, r[0].c_str());
	}
	m_impl->extensions = ext;
}

X509v3CertificateIssueExts
CertificateIssueData::getExtensions() const
{
	return m_impl->extensions;
}

void
CertificateIssueData::commit2Config(CA& ca, Type type) const
{
	if(!valid())
	{
		LOGIT_ERROR("invalid CertificateIssueData object");
		BLOCXX_THROW(limal::ValueException, "invalid CertificateIssueData object");
	}
	// These types are not supported by this object
	if(type == E_CRL        || type == E_Client_Req ||
	   type == E_Server_Req || type == E_CA_Req)
	{
		LOGIT_ERROR("wrong type" << type);
		BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
	}
	UInt32 t = (UInt32)((getEndDate() - getStartDate())/(60*60*24));
    
	ca.getConfig()->setValue(type2Section(type, false), "default_days", String(t));
                        
	String md("sha1");
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

blocxx::StringArray
CertificateIssueData::verify() const
{
	StringArray result;

	if(getStartDate() == 0)
	{
		result.append(Format("invalid notBefore: %1", getStartDate()).toString());
	}
	if(getEndDate() <= getStartDate())
	{
		result.append(Format("invalid notAfter %1 <= notBefore %2",
		                     getEndDate(), getStartDate())
		              .toString());
	}

	result.appendArray(m_impl->extensions.verify());
    
	LOGIT_DEBUG_STRINGARRAY("CertificateIssueData::verify()", result);

	return result;
}

blocxx::StringArray
CertificateIssueData::dump() const
{
	StringArray result;
	result.append("CertificateIssueData::dump()");

	result.append("!CHANGING DATA! notBefore = " + String(getStartDate()));
	result.append("!CHANGING DATA! notAfter = " + String(getEndDate()));
	result.append("notAfter - notBefore (in days)= " +
	              String((getEndDate() - getStartDate())/86400));
	result.append("MessageDigest = " + String(getMessageDigest()));
	result.appendArray(getExtensions().dump());

	return result;
}

}
}
