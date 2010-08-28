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

  File:       RequestData.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <ca-mgm/RequestData.hpp>
#include  <ca-mgm/ValueRegExCheck.hpp>
#include  <ca-mgm/Exception.hpp>


#include  "Utils.hpp"
#include  "RequestDataImpl.hpp"
#include  "X509v3RequestExtensions_Priv.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;


RequestData::RequestData(const RequestData& data)
	: m_impl(data.m_impl)
{}

RequestData::~RequestData()
{}

RequestData&
RequestData::operator=(const RequestData& data)
{
	if(this == &data) return *this;

	m_impl = data.m_impl;

	return *this;
}

uint32_t
RequestData::getVersion() const
{
	return m_impl->version;
}

uint32_t
RequestData::getKeysize() const
{
	return m_impl->keysize;
}

DNObject
RequestData::getSubjectDN() const
{
	return m_impl->subject;
}

KeyAlg
RequestData::getKeyAlgorithm() const
{
	return m_impl->pubkeyAlgorithm;
}

ByteBuffer
RequestData::getPublicKey() const
{
	return m_impl->publicKey;
}

SigAlg
RequestData::getSignatureAlgorithm() const
{
	return m_impl->signatureAlgorithm;
}

ByteBuffer
RequestData::getSignature() const
{
	return m_impl->signature;
}

X509v3RequestExts
RequestData::getExtensions() const
{
	return m_impl->extensions;
}

std::string
RequestData::getChallengePassword() const
{
	return m_impl->challengePassword;
}

std::string
RequestData::getUnstructuredName() const
{
	return m_impl->unstructuredName;
}

std::string
RequestData::getRequestAsText() const
{
	unsigned char *ustringval = NULL;
	unsigned int n = 0;
	BIO *bio = BIO_new(BIO_s_mem());

	X509_REQ_print_ex(bio, m_impl->x509, 0, 0);
	n = BIO_get_mem_data(bio, &ustringval);

	std::string text = std::string((const char*)ustringval, n);
	BIO_free(bio);

	return text;
}

std::string
RequestData::getExtensionsAsText() const
{
	unsigned char *ustringval = NULL;
	unsigned int n = 0;
	BIO *bio = BIO_new(BIO_s_mem());

	X509V3_extensions_print(bio, NULL, X509_REQ_get_extensions(m_impl->x509), 0, 4);
	n = BIO_get_mem_data(bio, &ustringval);

	std::string extText = std::string((const char*)ustringval, n);
	BIO_free(bio);

	return extText;
}

bool
RequestData::valid() const
{
	if(m_impl->version < 1 || m_impl->version > 1)
	{
		LOGIT_DEBUG("invalid version:" << m_impl->version);
		return false;
	}

	if(!m_impl->subject.valid()) return false;

	// keysize ?

	if(m_impl->publicKey.empty())
	{
		LOGIT_DEBUG("invalid publicKey");
		return false;
	}

	if(!m_impl->extensions.valid()) return false;

	return true;
}

std::vector<std::string>
RequestData::verify() const
{
	std::vector<std::string> result;

	if(m_impl->version < 1 || m_impl->version > 1)
	{
		result.push_back(str::form("invalid version: %d", m_impl->version));
	}

	appendArray(result, m_impl->subject.verify());

	// keysize ?

	if(m_impl->publicKey.empty())
	{
		result.push_back("invalid publicKey");
	}

	appendArray(result, m_impl->extensions.verify());

	LOGIT_DEBUG_STRINGARRAY("CertificateData::verify()", result);

	return result;
}

std::vector<std::string>
RequestData::dump() const
{
	std::vector<std::string> result;
	result.push_back("RequestData::dump()");

	result.push_back("Version = " + str::numstring(m_impl->version));
	appendArray(result, m_impl->subject.dump());
	result.push_back("Keysize = " + str::numstring(m_impl->keysize));
	result.push_back("pubkeyAlgorithm = " + str::numstring(m_impl->pubkeyAlgorithm));

	std::string pk;
	for(size_t i = 0; i < m_impl->publicKey.size(); ++i)
	{
		pk += str::form( "%02x", static_cast<uint8_t>(m_impl->publicKey[i])) + ":";
	}
	result.push_back("public Key = " + pk);

	result.push_back("signatureAlgorithm = "+ str::numstring(m_impl->signatureAlgorithm));

	std::string s;
	for(uint i = 0; i < m_impl->signature.size(); ++i)
	{
		s += str::form( "%02x", static_cast<uint8_t>(m_impl->signature[i])) + ":";
	}

	result.push_back("Signature = " + s);

	appendArray(result, m_impl->extensions.dump());
	result.push_back("Challenge Password = " + m_impl->challengePassword);
	result.push_back("Unstructured Name = " + m_impl->unstructuredName);

	return result;
}


//    protected:
RequestData::RequestData()
	: m_impl(new RequestDataImpl())
{}

}
