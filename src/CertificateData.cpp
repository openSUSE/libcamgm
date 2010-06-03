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
#include  <blocxx/COWIntrusiveCountableBase.hpp>

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

blocxx::UInt32
CertificateData::getVersion() const
{
	return m_impl->version;
}

blocxx::String
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

blocxx::UInt32
CertificateData::getKeysize() const
{
	return m_impl->keysize;
}

KeyAlg
CertificateData::getPublicKeyAlgorithm() const
{
	return m_impl->pubkeyAlgorithm;
}

blocxx::String
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
	return String();
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

blocxx::String
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
	return String();
}

ByteBuffer
	CertificateData::getSignature() const
{
	return m_impl->signature;
}

blocxx::String
	CertificateData::getFingerprint() const
{
	return m_impl->fingerprint;
}

X509v3CertificateExts
	CertificateData::getExtensions() const
{
	return m_impl->extensions;
}

String
CertificateData::getCertificateAsText() const
{
	unsigned char *ustringval = NULL;
	unsigned int n = 0;
	BIO *bio = BIO_new(BIO_s_mem());

	X509_print_ex(bio, m_impl->x509, 0, 0);
	n = BIO_get_mem_data(bio, &ustringval);

	String text = String((const char*)ustringval, n);
	BIO_free(bio);

	return text;
}

String
CertificateData::getExtensionsAsText() const
{
	unsigned char *ustringval = NULL;
	unsigned int n = 0;
	BIO *bio = BIO_new(BIO_s_mem());

	X509V3_extensions_print(bio, NULL, m_impl->x509->cert_info->extensions, 0, 4);
	n = BIO_get_mem_data(bio, &ustringval);

	String extText = String((const char*)ustringval, n);
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

blocxx::StringArray
CertificateData::verify() const
{
	StringArray result;

	if(m_impl->version < 1 || m_impl->version > 3)
	{
		result.append(Format("invalid version: %1", m_impl->version).toString());
	}

	if(!initHexCheck().isValid(m_impl->serial))
	{
		result.append(Format("invalid serial: %1", m_impl->serial).toString());
	}

	if(m_impl->notBefore == 0)
	{
		result.append(Format("invalid notBefore: %1", m_impl->notBefore).toString());
	}
	if(m_impl->notAfter <= m_impl->notBefore)
	{
		result.append(Format("invalid notAfter: %1", m_impl->notAfter).toString());
	}
	result.appendArray(m_impl->issuer.verify());
	result.appendArray(m_impl->subject.verify());

	// keysize ?

	if(m_impl->publicKey.empty())
	{
		result.append("invalid publicKey");
	}

	result.appendArray(m_impl->extensions.verify());

	LOGIT_DEBUG_STRINGARRAY("CertificateData::verify()", result);

	return result;
}

blocxx::StringArray
CertificateData::dump() const
{
	StringArray result;
	result.append("CertificateData::dump()");

	result.append("Version = " + String(m_impl->version));
	result.append("Serial = " + m_impl->serial);
	result.append("notBefore = " + String(m_impl->notBefore));
	result.append("notAfter = " + String(m_impl->notAfter));
	result.append("Fingerprint = " + m_impl->fingerprint);
	result.appendArray(m_impl->issuer.dump());
	result.appendArray(m_impl->subject.dump());
	result.append("Keysize = " + String(m_impl->keysize));
	result.append("public key algorithm = " + String(m_impl->pubkeyAlgorithm));

	String pk;
	for(size_t i = 0; i < m_impl->publicKey.size(); ++i)
	{
		String s;
		s.format("%02x", (UInt8)m_impl->publicKey[i]);
		pk += s + ":";
	}
	result.append("public Key = " + pk);
	result.append("signatureAlgorithm = "+ String(m_impl->signatureAlgorithm));

	String s;
	for(uint i = 0; i < m_impl->signature.size(); ++i)
	{
		String d;
		d.format("%02x:", (UInt8)m_impl->signature[i]);
		s += d;
	}

	result.append("Signature = " + s);
	result.appendArray(m_impl->extensions.dump());

	return result;
}

//    protected
CertificateData::CertificateData()
	: m_impl(new CertificateDataImpl())
{}

}
