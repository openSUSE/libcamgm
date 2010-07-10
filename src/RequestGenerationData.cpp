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



#include  "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;
using namespace blocxx;

class RequestGenerationDataImpl
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
		: subject(impl.subject)
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
	uint32_t    keysize;

	// KeyAlg         pubkeyAlgorithm;  // at the beginning we only support rsa


	MD                messageDigest;       // parameter default_md

	// attributes
	std::string            challengePassword;
	std::string            unstructuredName;

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
	m_impl->keysize = str::strtonum<uint32_t>(caConfig->getValue(type2Section(type, false), "default_bits"));

	std::string md = caConfig->getValue(type2Section(type, false), "default_md");
	if(0 == str::compareCI(md, "sha1"))
	{
		m_impl->messageDigest = E_SHA1;
	}
	else if(0 == str::compareCI(md, "md5"))
	{
		m_impl->messageDigest = E_MD5;
	}
	else if(0 == str::compareCI(md, "mdc2"))
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
	std::vector<std::string> r = dn.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		CA_MGM_THROW(ca_mgm::ValueException, r[0].c_str());
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
RequestGenerationData::setKeysize(uint32_t size)
{
	m_impl->keysize = size;
}

uint32_t
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
RequestGenerationData::setChallengePassword(const std::string &passwd)
{
	m_impl->challengePassword = passwd;
}

std::string
RequestGenerationData::getChallengePassword() const
{
	return m_impl->challengePassword;
}

void
RequestGenerationData::setUnstructuredName(const std::string &name)
{
	m_impl->unstructuredName = name;
}

std::string
RequestGenerationData::getUnstructuredName() const
{
	return m_impl->unstructuredName;
}

void
RequestGenerationData::setExtensions(const X509v3RequestExts &ext)
{
	std::vector<std::string> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		CA_MGM_THROW(ca_mgm::ValueException, r[0].c_str());
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
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid RequestGenerationData object."));
	}

	if(type == E_CRL         || type == E_Client_Cert ||
	   type == E_Server_Cert || type == E_CA_Cert )
	{
		LOGIT_ERROR("wrong type" << type);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Wrong type: %1."), type).c_str());
	}

	ca.getConfig()->setValue(type2Section(type, false), "default_bits", str::numstring(m_impl->keysize));

	std::string md("sha1");
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

std::vector<std::string>
RequestGenerationData::verify() const
{
	std::vector<std::string> result;

	appendArray(result, m_impl->subject.verify());

	// keysize??

	appendArray(result, m_impl->extensions.verify());

	LOGIT_DEBUG_STRINGARRAY("RequestGenerationData::verify()", result);

	return result;
}

std::vector<std::string>
RequestGenerationData::dump() const
{
	std::vector<std::string> result;
	result.push_back("RequestGenerationData::dump()");

	appendArray(result, m_impl->subject.dump());
	result.push_back("Keysize = " + str::numstring(m_impl->keysize));
	result.push_back("MessageDigest = " + str::numstring(m_impl->messageDigest));
	result.push_back("Challenge Password = " + m_impl->challengePassword);
	result.push_back("Unstructured Name = " + m_impl->unstructuredName);
	appendArray(result, m_impl->extensions.dump());

	return result;
}

}
