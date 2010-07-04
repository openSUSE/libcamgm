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

  File:       CertificateData.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/CertificateData.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>


#include  "CertificateDataImpl.hpp"
#include  "Utils.hpp"
#include  "X509v3CertificateExtensions_Priv.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;
using namespace blocxx;


CertificateData::CertificateData(const CertificateData& data)
	: m_impl(data.m_impl)
{}

CertificateData::~CertificateData()
{}

CertificateData&
	CertificateData::operator=(const CertificateData& data)
{
	if(this == &data) return *this;

	m_impl = data.m_impl;

	return *this;
}

uint32_t
CertificateData::getVersion() const
{
	return m_impl->version;
}

std::string
CertificateData::getSerial() const
{
	return m_impl->serial;
}

time_t
CertificateData::getStartDate() const
{
	return m_impl->notBefore;
}

time_t
CertificateData::getEndDate() const
{
	return m_impl->notAfter;
}

DNObject
CertificateData::getIssuerDN() const
{
	return m_impl->issuer;
}

DNObject
CertificateData::getSubjectDN() const
{
	return m_impl->subject;
}

uint32_t
CertificateData::getKeysize() const
{
	return m_impl->keysize;
}

KeyAlg
CertificateData::getPublicKeyAlgorithm() const
{
	return m_impl->pubkeyAlgorithm;
}

std::string
CertificateData::getPublicKeyAlgorithmAsString() const
{
	switch(m_impl->pubkeyAlgorithm)
	{
	case E_RSA:
		return "RSA";
		break;
	case E_DSA:
		return "DSA";
		break;
	case E_DH:
		return "DH";
		break;
	}
	return std::string();
}

ByteBuffer
CertificateData::getPublicKey() const
{
	return m_impl->publicKey;
}

SigAlg
CertificateData::getSignatureAlgorithm() const
{
	return m_impl->signatureAlgorithm;
}

std::string
CertificateData::getSignatureAlgorithmAsString() const
{
	switch(m_impl->signatureAlgorithm)
	{
	case E_SHA1RSA:
		return "SHA1RSA";
		break;
	case E_MD5RSA:
		return "MD5RSA";
		break;
	case E_SHA1DSA:
		return "SHA1DSA";
		break;
	}
	return std::string();
}

ByteBuffer
	CertificateData::getSignature() const
{
	return m_impl->signature;
}

std::string
	CertificateData::getFingerprint() const
{
	return m_impl->fingerprint;
}

X509v3CertificateExts
	CertificateData::getExtensions() const
{
	return m_impl->extensions;
}

std::string
CertificateData::getCertificateAsText() const
{
	unsigned char *ustringval = NULL;
	unsigned int n = 0;
	BIO *bio = BIO_new(BIO_s_mem());

	X509_print_ex(bio, m_impl->x509, 0, 0);
	n = BIO_get_mem_data(bio, &ustringval);

	std::string text = std::string((const char*)ustringval, n);
	BIO_free(bio);

	return text;
}

std::string
CertificateData::getExtensionsAsText() const
{
	unsigned char *ustringval = NULL;
	unsigned int n = 0;
	BIO *bio = BIO_new(BIO_s_mem());

	X509V3_extensions_print(bio, NULL, m_impl->x509->cert_info->extensions, 0, 4);
	n = BIO_get_mem_data(bio, &ustringval);

	std::string extText = std::string((const char*)ustringval, n);
	BIO_free(bio);

	return extText;
}

bool
CertificateData::valid() const
{
	if(m_impl->version < 1 || m_impl->version > 3)
	{
		LOGIT_DEBUG("invalid version:" << m_impl->version);
		return false;
	}

	if(!initHexCheck().isValid(m_impl->serial))
	{
		LOGIT_DEBUG("invalid serial:" << m_impl->serial);
		return false;
	}

	if(m_impl->notBefore == 0)
	{
		LOGIT_DEBUG("invalid notBefore:" << m_impl->notBefore);
		return false;
	}

	if(m_impl->notAfter <= m_impl->notBefore)
	{
		LOGIT_DEBUG("invalid notAfter:" << m_impl->notAfter);
		return false;
	}

	if(!m_impl->issuer.valid())  return false;
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
CertificateData::verify() const
{
	std::vector<std::string> result;

	if(m_impl->version < 1 || m_impl->version > 3)
	{
		result.push_back(str::form("invalid version: %d", m_impl->version));
	}

	if(!initHexCheck().isValid(m_impl->serial))
	{
		result.push_back(str::form("invalid serial: %s", m_impl->serial.c_str()));
	}

	if(m_impl->notBefore == 0)
	{
		result.push_back(str::form("invalid notBefore: %ld", m_impl->notBefore));
	}
	if(m_impl->notAfter <= m_impl->notBefore)
	{
		result.push_back(str::form("invalid notAfter: %ld", m_impl->notAfter));
	}
	appendArray(result, m_impl->issuer.verify());
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
CertificateData::dump() const
{
	std::vector<std::string> result;
	result.push_back("CertificateData::dump()");

	result.push_back("Version = " + str::numstring(m_impl->version));
	result.push_back("Serial = " + m_impl->serial);
	result.push_back("notBefore = " + str::numstring(m_impl->notBefore));
	result.push_back("notAfter = " + str::numstring(m_impl->notAfter));
	result.push_back("Fingerprint = " + m_impl->fingerprint);
	appendArray(result, m_impl->issuer.dump());
	appendArray(result, m_impl->subject.dump());
	result.push_back("Keysize = " + str::numstring(m_impl->keysize));
	result.push_back("public key algorithm = " + str::numstring(m_impl->pubkeyAlgorithm));

	std::string pk;
	for(size_t i = 0; i < m_impl->publicKey.size(); ++i)
	{
      pk += str::form( "%02x", (UInt8)m_impl->publicKey[i] ) + ":";
	}
	result.push_back("public Key = " + pk);
	result.push_back("signatureAlgorithm = "+ str::numstring(m_impl->signatureAlgorithm));

	std::string s;
	for(uint i = 0; i < m_impl->signature.size(); ++i)
	{
      s += str::form( "%02x", (UInt8)m_impl->signature[i] ) + ":";
	}

	result.push_back("Signature = " + s);
	appendArray(result, m_impl->extensions.dump());

	return result;
}

//    protected
CertificateData::CertificateData()
	: m_impl(new CertificateDataImpl())
{}

}
