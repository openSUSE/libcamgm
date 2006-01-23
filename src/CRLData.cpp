#/*---------------------------------------------------------------------\
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

  File:       CRLData.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/CRLData.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>
#include  <blocxx/COWIntrusiveCountableBase.hpp>

#include  "CRLDataImpl.hpp"
#include  "DNObject_Priv.hpp"
#include  "Utils.hpp"
#include  "X509v3CRLExtensions_Priv.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;

	
RevocationEntry::RevocationEntry()
	: m_impl(new RevocationEntryImpl())
{}

RevocationEntry::RevocationEntry(const RevocationEntry& entry)
	: m_impl(entry.m_impl)
{}

RevocationEntry::~RevocationEntry()
{}

RevocationEntry& 
RevocationEntry::operator=(const RevocationEntry& entry)
{
	if(this == &entry) return *this;
    
	m_impl = entry.m_impl;
    
	return *this;
}

blocxx::String
RevocationEntry::getSerial() const
{
	return m_impl->serial;
}

time_t
RevocationEntry::getRevocationDate() const
{
	return m_impl->revocationDate;
}

CRLReason
RevocationEntry::getReason() const
{
	return m_impl->revocationReason;
}

bool
RevocationEntry::valid() const
{
	if(!initHexCheck().isValid(m_impl->serial))
	{
		LOGIT_DEBUG("invalid serial: "<< m_impl->serial);
		return false;
	}
	return m_impl->revocationReason.valid();
}

blocxx::StringArray
RevocationEntry::verify() const
{
	StringArray result;
    
	if(!initHexCheck().isValid(m_impl->serial))
	{
		result.append(Format("invalid serial: %1", m_impl->serial).toString());
	}
	result.appendArray(m_impl->revocationReason.verify());

	LOGIT_DEBUG_STRINGARRAY("RevocationEntry::verify()", result);
    
	return result;
}

blocxx::StringArray
RevocationEntry::dump() const
{
	StringArray result;
	result.append("RevocationEntry::dump()");

	result.append("Serial = " + m_impl->serial);
	result.append("revocation Date = " + String(m_impl->revocationDate));
	result.appendArray(m_impl->revocationReason.dump());

	return result;
}


// ##################################################################

CRLData::CRLData(const CRLData& data)
	: m_impl(data.m_impl)
{}

CRLData::~CRLData()
{}

CRLData& 
CRLData::operator=(const CRLData& data)
{
	if(this == &data) return *this;

	m_impl = data.m_impl;

	return *this;
}

blocxx::Int32
CRLData::getVersion() const
{
	return m_impl->version;
}

blocxx::String
CRLData::getFingerprint() const
{
	return m_impl->fingerprint;
}

time_t
CRLData::getLastUpdateDate() const
{
	return m_impl->lastUpdate;
}

time_t
CRLData::getNextUpdateDate() const
{
	return m_impl->nextUpdate;
}

DNObject
CRLData::getIssuerDN() const
{
	return m_impl->issuer;
}

SigAlg
CRLData::getSignatureAlgorithm() const
{
	return m_impl->signatureAlgorithm;
}

blocxx::String
CRLData::getSignatureAlgorithmAsString() const
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
CRLData::getSignature() const
{
	return m_impl->signature;
}

X509v3CRLExts
CRLData::getExtensions() const
{
	return m_impl->extensions;
}

blocxx::Map<blocxx::String, RevocationEntry>
CRLData::getRevocationData() const
{
	return m_impl->revocationData;
}

RevocationEntry
CRLData::getRevocationEntry(const String& oid)
{
	if(m_impl->revocationData.find(oid) != m_impl->revocationData.end())
	{
		return (*(m_impl->revocationData.find(oid))).second;
	}
	LOGIT_ERROR("Entry not found: " << oid);
	BLOCXX_THROW(limal::ValueException, "Entry not found");
}

blocxx::String
CRLData::getCRLAsText() const
{
	return m_impl->text;
}

blocxx::String
CRLData::getExtensionsAsText() const
{
	return m_impl->extText;
}

bool
CRLData::valid() const
{
	if(m_impl->version < 1 || m_impl->version > 2)
	{
		LOGIT_DEBUG("invalid version: " << m_impl->version);
		return false;
	}
	if(m_impl->lastUpdate == 0)
	{
		LOGIT_DEBUG("invalid lastUpdate:" << m_impl->lastUpdate);
		return false;
	}
	if(m_impl->nextUpdate <= m_impl->lastUpdate)
	{
		LOGIT_DEBUG("invalid nextUpdate:" << m_impl->nextUpdate);
		return false;
	}
	if(!m_impl->issuer.valid())  return false;

	if(!m_impl->extensions.valid()) return false;

	StringArray r = checkRevocationData(m_impl->revocationData);
	if(!r.empty())
	{
		LOGIT_DEBUG(r[0]);
		return false;
	}
	return true;
}

blocxx::StringArray
CRLData::verify() const
{
	StringArray result;
    
	if(m_impl->version < 1 || m_impl->version > 2)
	{
		result.append(Format("invalid version: %1", m_impl->version).toString());
	}
	if(m_impl->lastUpdate == 0)
	{
		result.append(Format("invalid lastUpdate: %1", m_impl->lastUpdate).toString());
	}
	if(m_impl->nextUpdate <= m_impl->lastUpdate)
	{
		result.append(Format("invalid nextUpdate: %1", m_impl->nextUpdate).toString());
	}
	result.appendArray(m_impl->issuer.verify());

	result.appendArray(m_impl->extensions.verify());
	result.appendArray(checkRevocationData(m_impl->revocationData));

	LOGIT_DEBUG_STRINGARRAY("CRLData::verify()", result);
    
	return result;
}

blocxx::StringArray
CRLData::dump() const
{
	StringArray result;
	result.append("CRLData::dump()");

	result.append("Version = " + String(m_impl->version));
	result.append("Fingerprint = " + m_impl->fingerprint);
	result.append("last Update = " + String(m_impl->lastUpdate));
	result.append("next Update = " + String(m_impl->nextUpdate));
	result.appendArray(m_impl->issuer.dump());
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

	blocxx::Map< String, RevocationEntry >::const_iterator it = m_impl->revocationData.begin();
	for(; it != m_impl->revocationData.end(); ++it)
	{
		result.append((*it).first);
		result.appendArray(((*it).second).dump());
	}

	return result;
}

//    protected:
CRLData::CRLData()
	: m_impl(new CRLDataImpl())
{}

StringArray
CRLData::checkRevocationData(const blocxx::Map<String, RevocationEntry>& rd) const
{
	StringArray result;
	blocxx::Map<String, RevocationEntry>::const_iterator it = rd.begin();
	for(; it != rd.end(); ++it)
	{
		result.appendArray(((*it).second).verify());
	}
	return result;
}

}
}
