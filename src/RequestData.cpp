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

#include  <limal/ca-mgm/RequestData.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

#include  "Utils.hpp"
#include  "RequestDataImpl.hpp"
#include  "X509v3RequestExtensions_Priv.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;


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

blocxx::UInt32
RequestData::getVersion() const
{
	return m_impl->version;
}

blocxx::UInt32
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

blocxx::String
RequestData::getChallengePassword() const
{
	return m_impl->challengePassword;
}

blocxx::String
RequestData::getUnstructuredName() const
{
	return m_impl->unstructuredName;
}

blocxx::String
RequestData::getRequestAsText() const
{
	return m_impl->text;
}

blocxx::String
RequestData::getExtensionsAsText() const
{
	return m_impl->extText;
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

blocxx::StringArray
RequestData::verify() const
{
	StringArray result;

	if(m_impl->version < 1 || m_impl->version > 1)
	{
		result.append(Format("invalid version: %1", m_impl->version).toString());
	}

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
RequestData::dump() const
{
	StringArray result;
	result.append("RequestData::dump()");
    
	result.append("Version = " + String(m_impl->version));
	result.appendArray(m_impl->subject.dump());
	result.append("Keysize = " + String(m_impl->keysize));
	result.append("pubkeyAlgorithm = " + String(m_impl->pubkeyAlgorithm));
    
	String pk;
	for(size_t i = 0; i < m_impl->publicKey.size(); ++i)
	{
		String s;
		s.format("%02x", static_cast<UInt8>(m_impl->publicKey[i]));
		pk += s + ":";
	}
	result.append("public Key = " + pk);
    
	result.append("signatureAlgorithm = "+ String(m_impl->signatureAlgorithm));

	String s;
	for(uint i = 0; i < m_impl->signature.size(); ++i)
	{
		String d;
		d.format("%02x:", static_cast<UInt8>(m_impl->signature[i]));
		s += d;
	}

	result.append("Signature = " + s);

	result.appendArray(m_impl->extensions.dump());
	result.append("Challenge Password = " + m_impl->challengePassword);
	result.append("Unstructured Name = " + m_impl->unstructuredName);
    
	return result;
}


//    protected:
RequestData::RequestData()
	: m_impl(new RequestDataImpl())
{}

}
}
