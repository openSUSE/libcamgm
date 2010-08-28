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

  File:       CRLGenerationData.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <ca-mgm/CA.hpp>
#include  <ca-mgm/CRLGenerationData.hpp>
#include  <ca-mgm/Exception.hpp>


#include  "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;

class CRLGenerationDataImpl
{
public:

	CRLGenerationDataImpl()
		: crlHours(0)
		, extensions(X509v3CRLGenerationExts())
	{}

	CRLGenerationDataImpl(uint32_t hours,
	                      const X509v3CRLGenerationExts& ext)
		: crlHours(hours)
		, extensions(ext)
	{}

	CRLGenerationDataImpl(const CRLGenerationDataImpl& impl)
		: crlHours(impl.crlHours)
		, extensions(impl.extensions)
	{}

	~CRLGenerationDataImpl() {}

	CRLGenerationDataImpl* clone() const
	{
		return new CRLGenerationDataImpl(*this);
	}

	uint32_t                crlHours;
	X509v3CRLGenerationExts       extensions;

};


CRLGenerationData::CRLGenerationData()
	: m_impl(new CRLGenerationDataImpl())
{}

CRLGenerationData::CRLGenerationData(CAConfig* caConfig, Type type)
	: m_impl(new CRLGenerationDataImpl())
{
	m_impl->extensions = X509v3CRLGenerationExts(caConfig, type);
	m_impl->crlHours = str::strtonum<uint32_t>(caConfig->getValue(type2Section(type, false), "default_crl_hours"));
}

CRLGenerationData::CRLGenerationData(uint32_t hours,
                                     const X509v3CRLGenerationExts& ext)
	: m_impl(new CRLGenerationDataImpl(hours, ext))
{
	std::vector<std::string> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		CA_MGM_THROW(ca_mgm::ValueException, r[0].c_str());
	}
}

CRLGenerationData::CRLGenerationData(const CRLGenerationData& data)
	: m_impl(data.m_impl)
{}

CRLGenerationData::~CRLGenerationData()
{}

CRLGenerationData&
CRLGenerationData::operator=(const CRLGenerationData& data)
{
	if(this == &data) return *this;

	m_impl = data.m_impl;

	return *this;
}

void
CRLGenerationData::setCRLLifeTime(uint32_t hours)
{
	m_impl->crlHours = hours;
}

uint32_t
CRLGenerationData::getCRLLifeTime() const
{
	return m_impl->crlHours;
}

void
CRLGenerationData::setExtensions(const X509v3CRLGenerationExts& ext)
{
	std::vector<std::string> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		CA_MGM_THROW(ca_mgm::ValueException, r[0].c_str());
	}
	m_impl->extensions = ext;
}

X509v3CRLGenerationExts
CRLGenerationData::getExtensions() const
{
	return m_impl->extensions;
}

X509v3CRLGenerationExts&
CRLGenerationData::extensions()
{
	return m_impl->extensions;
}

void
CRLGenerationData::commit2Config(CA& ca, Type type) const
{
	if(!valid())
	{
		LOGIT_ERROR("invalid CRLGenerationData object");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid CRLGenerationData object."));
	}
	// These types are not supported by this object
	if(type != E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %d."), type).c_str());
	}

	ca.getConfig()->setValue(type2Section(type, false),
	                         "default_crl_hours",
	                         str::numstring(m_impl->crlHours));

	m_impl->extensions.commit2Config(ca, type);
}

bool
CRLGenerationData::valid() const
{
	if(m_impl->crlHours == 0)
	{
		LOGIT_DEBUG("invalid crlhours: " << m_impl->crlHours);
		return false;
	}
	return m_impl->extensions.valid();
}

std::vector<std::string>
CRLGenerationData::verify() const
{
	std::vector<std::string> result;

	if(m_impl->crlHours == 0)
	{
		result.push_back(str::form("invalid crlhours: %d", m_impl->crlHours));
	}
	appendArray(result, m_impl->extensions.verify());

	LOGIT_DEBUG_STRINGARRAY("CRLGenerationData::verify()", result);

	return result;
}

std::vector<std::string>
CRLGenerationData::dump() const
{
	std::vector<std::string> result;
	result.push_back("CRLGenerationData::dump()");

	result.push_back("CRL Hours = " + str::numstring(m_impl->crlHours));
	appendArray(result, m_impl->extensions.dump());

	return result;
}

}

