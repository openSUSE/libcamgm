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

#include  <limal/ca-mgm/CA.hpp>
#include  <limal/ca-mgm/CRLGenerationData.hpp>
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

class CRLGenerationDataImpl : public blocxx::COWIntrusiveCountableBase
{
public:

	CRLGenerationDataImpl()
		: crlHours(0)
		, extensions(X509v3CRLGenerationExts())
	{}

	CRLGenerationDataImpl(blocxx::UInt32 hours,
	                      const X509v3CRLGenerationExts& ext)
		: crlHours(hours)
		, extensions(ext)
	{}

	CRLGenerationDataImpl(const CRLGenerationDataImpl& impl)
		: COWIntrusiveCountableBase(impl)
		, crlHours(impl.crlHours)
		, extensions(impl.extensions)
	{}

	~CRLGenerationDataImpl() {}

	CRLGenerationDataImpl* clone() const
	{
		return new CRLGenerationDataImpl(*this);
	}

	blocxx::UInt32                crlHours;
	X509v3CRLGenerationExts       extensions;

};


CRLGenerationData::CRLGenerationData()
	: m_impl(new CRLGenerationDataImpl())
{}

CRLGenerationData::CRLGenerationData(CAConfig* caConfig, Type type)
	: m_impl(new CRLGenerationDataImpl())
{
	m_impl->extensions = X509v3CRLGenerationExts(caConfig, type);
	m_impl->crlHours = caConfig->getValue(type2Section(type, false), "default_crl_hours").toUInt32();
}

CRLGenerationData::CRLGenerationData(blocxx::UInt32 hours,
                                     const X509v3CRLGenerationExts& ext)
	: m_impl(new CRLGenerationDataImpl(hours, ext))
{
	StringArray r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(limal::ValueException, r[0].c_str());
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
CRLGenerationData::setCRLLifeTime(blocxx::UInt32 hours)
{
	m_impl->crlHours = hours;
}

blocxx::UInt32
CRLGenerationData::getCRLLifeTime() const
{
	return m_impl->crlHours;
}

void
CRLGenerationData::setExtensions(const X509v3CRLGenerationExts& ext)
{
	StringArray r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(limal::ValueException, r[0].c_str());
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
		BLOCXX_THROW(limal::ValueException,
		             __("Invalid CRLGenerationData object."));
	}
	// These types are not supported by this object
	if(type != E_CRL)
	{
		LOGIT_ERROR("wrong type" << type);
		BLOCXX_THROW(limal::ValueException,
		             Format(__("Wrong type: %1."), type).c_str());
	}

	ca.getConfig()->setValue(type2Section(type, false),
	                         "default_crl_hours",
	                         String(m_impl->crlHours));

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

blocxx::StringArray
CRLGenerationData::verify() const
{
	StringArray result;

	if(m_impl->crlHours == 0)
	{
		result.append(Format("invalid crlhours: %1", m_impl->crlHours).toString());
	}
	result.appendArray(m_impl->extensions.verify());

	LOGIT_DEBUG_STRINGARRAY("CRLGenerationData::verify()", result);

	return result;
}

blocxx::StringArray
CRLGenerationData::dump() const
{
	StringArray result;
	result.append("CRLGenerationData::dump()");

	result.append("CRL Hours = " + String(m_impl->crlHours));
	result.appendArray(m_impl->extensions.dump());

	return result;
}

}
}

