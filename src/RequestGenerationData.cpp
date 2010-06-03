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

  File:       RequestGenerationData.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/


#include  <limal/ca-mgm/RequestGenerationData.hpp>
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>
#include  <blocxx/COWIntrusiveCountableBase.hpp>

#include  "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;
using namespace blocxx;

class RequestGenerationDataImpl : public blocxx::COWIntrusiveCountableBase
{
public:
	RequestGenerationDataImpl()
		: subject(DNObject())
		, keysize(0)
		, messageDigest(E_SHA1)
		, challengePassword("")
		, unstructuredName("")
		, extensions(X509v3RequestExts())
	{}

	RequestGenerationDataImpl(const RequestGenerationDataImpl& impl)
		: COWIntrusiveCountableBase(impl)
		, subject(impl.subject)
		, keysize(impl.keysize)
		, messageDigest(impl.messageDigest)
		, challengePassword(impl.challengePassword)
		, unstructuredName(impl.unstructuredName)
		, extensions(impl.extensions)
	{}

	~RequestGenerationDataImpl() {}

	RequestGenerationDataImpl* clone() const
	{
		return new RequestGenerationDataImpl(*this);
	}

	DNObject          subject;
	blocxx::UInt32    keysize;

	// KeyAlg         pubkeyAlgorithm;  // at the beginning we only support rsa


	MD                messageDigest;       // parameter default_md

	// attributes
	String            challengePassword;
	String            unstructuredName;

	X509v3RequestExts extensions;

};


RequestGenerationData::RequestGenerationData()
	: m_impl(new RequestGenerationDataImpl())
{}

RequestGenerationData::RequestGenerationData(CAConfig* caConfig, Type type)
	: m_impl(new RequestGenerationDataImpl())
{
	m_impl->subject = DNObject(caConfig, type);
	m_impl->extensions = X509v3RequestExts(caConfig, type);
	m_impl->keysize = caConfig->getValue(type2Section(type, false), "default_bits").toUInt32();

	String md = caConfig->getValue(type2Section(type, false), "default_md");
	if(md.equalsIgnoreCase("sha1"))
	{
		m_impl->messageDigest = E_SHA1;
	}
	else if(md.equalsIgnoreCase("md5"))
	{
		m_impl->messageDigest = E_MD5;
	}
	else if(md.equalsIgnoreCase("mdc2"))
	{
		m_impl->messageDigest = E_MDC2;
	}
	else
	{
		LOGIT_INFO("unsupported message digest: " << md);
		LOGIT_INFO("select default sha1.");
		m_impl->messageDigest = E_SHA1;
	}
}

RequestGenerationData::RequestGenerationData(const RequestGenerationData& data)
	: m_impl(data.m_impl)
{}

RequestGenerationData::~RequestGenerationData()
{}

RequestGenerationData&
RequestGenerationData::operator=(const RequestGenerationData& data)
{
	if(this == &data) return *this;

	m_impl = data.m_impl;

	return *this;
}

void
RequestGenerationData::setSubjectDN(const DNObject dn)
{
	StringArray r = dn.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(ca_mgm::ValueException, r[0].c_str());
	}
	m_impl->subject = dn;
}

DNObject
RequestGenerationData::getSubjectDN() const
{
	return m_impl->subject;
}

DNObject&
RequestGenerationData::subjectDN()
{
	return m_impl->subject;
}

void
RequestGenerationData::setKeysize(blocxx::UInt32 size)
{
	m_impl->keysize = size;
}

blocxx::UInt32
RequestGenerationData::getKeysize() const
{
	return m_impl->keysize;
}

void
RequestGenerationData::setMessageDigest(MD md)
{
	m_impl->messageDigest = md;
}

MD
RequestGenerationData::getMessageDigest() const
{
	return m_impl->messageDigest;
}

void
RequestGenerationData::setChallengePassword(const String &passwd)
{
	m_impl->challengePassword = passwd;
}

blocxx::String
RequestGenerationData::getChallengePassword() const
{
	return m_impl->challengePassword;
}

void
RequestGenerationData::setUnstructuredName(const String &name)
{
	m_impl->unstructuredName = name;
}

blocxx::String
RequestGenerationData::getUnstructuredName() const
{
	return m_impl->unstructuredName;
}

void
RequestGenerationData::setExtensions(const X509v3RequestExts &ext)
{
	StringArray r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(ca_mgm::ValueException, r[0].c_str());
	}
	m_impl->extensions = ext;
}

X509v3RequestExts
RequestGenerationData::getExtensions() const
{
	return m_impl->extensions;
}

X509v3RequestExts&
RequestGenerationData::extensions()
{
	return m_impl->extensions;
}

void
RequestGenerationData::commit2Config(CA& ca, Type type) const
{
	// do not use this->valid(); it checks for subject too
	// subject.valid() is not needed here
	if(!m_impl->extensions.valid())
	{
		LOGIT_ERROR("invalid RequestGenerationData object");
		BLOCXX_THROW(ca_mgm::ValueException,
		             __("Invalid RequestGenerationData object."));
	}

	if(type == E_CRL         || type == E_Client_Cert ||
	   type == E_Server_Cert || type == E_CA_Cert )
	{
		LOGIT_ERROR("wrong type" << type);
		BLOCXX_THROW(ca_mgm::ValueException,
		             Format(__("Wrong type: %1."), type).c_str());
	}

	ca.getConfig()->setValue(type2Section(type, false), "default_bits", String(m_impl->keysize));

	String md("sha1");
	switch(m_impl->messageDigest)
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
RequestGenerationData::valid() const
{
	if(!m_impl->subject.valid()) return false;

	// keysize??

	return m_impl->extensions.valid();
}

blocxx::StringArray
RequestGenerationData::verify() const
{
	StringArray result;

	result.appendArray(m_impl->subject.verify());

	// keysize??

	result.appendArray(m_impl->extensions.verify());

	LOGIT_DEBUG_STRINGARRAY("RequestGenerationData::verify()", result);

	return result;
}

blocxx::StringArray
RequestGenerationData::dump() const
{
	StringArray result;
	result.append("RequestGenerationData::dump()");

	result.appendArray(m_impl->subject.dump());
	result.append("Keysize = " + String(m_impl->keysize));
	result.append("MessageDigest = " + String(m_impl->messageDigest));
	result.append("Challenge Password = " + m_impl->challengePassword);
	result.append("Unstructured Name = " + m_impl->unstructuredName);
	result.appendArray(m_impl->extensions.dump());

	return result;
}

}
