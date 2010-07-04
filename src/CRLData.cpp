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

  File:       CRLData.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/CRLData.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>



#include  "CRLDataImpl.hpp"
#include  "DNObject_Priv.hpp"
#include  "Utils.hpp"
#include  "X509v3CRLExtensions_Priv.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;
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

std::string
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

std::vector<std::string>
RevocationEntry::verify() const
{
	std::vector<std::string> result;

	if(!initHexCheck().isValid(m_impl->serial))
	{
		result.push_back(str::form("invalid serial: %s", m_impl->serial.c_str()));
	}
	appendArray(result, m_impl->revocationReason.verify());

	LOGIT_DEBUG_STRINGARRAY("RevocationEntry::verify()", result);

	return result;
}

std::vector<std::string>
RevocationEntry::dump() const
{
	std::vector<std::string> result;
	result.push_back("RevocationEntry::dump()");

	result.push_back("Serial = " + m_impl->serial);
	result.push_back("revocation Date = " + str::numstring(m_impl->revocationDate));
	appendArray(result, m_impl->revocationReason.dump());

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

int32_t
CRLData::getVersion() const
{
	return m_impl->version;
}

std::string
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

std::string
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
	return std::string();
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

std::map<std::string, RevocationEntry>
CRLData::getRevocationData() const
{
	return m_impl->revocationData;
}

RevocationEntry
CRLData::getRevocationEntry(const std::string& oid)
{
	if(m_impl->revocationData.find(oid) != m_impl->revocationData.end())
	{
		return (*(m_impl->revocationData.find(oid))).second;
	}
	LOGIT_ERROR("Entry not found: " << oid);
	BLOCXX_THROW(ca_mgm::ValueException,
	             __("Entry not found."));
}

std::string
CRLData::getCRLAsText() const
{
	unsigned char *ustringval = NULL;
	unsigned int n = 0;
	BIO *bio = BIO_new(BIO_s_mem());

	X509_CRL_print(bio, m_impl->x509);
	n = BIO_get_mem_data(bio, &ustringval);

	std::string text = std::string((const char*)ustringval, n);
	BIO_free(bio);

	return text;
}

std::string
CRLData::getExtensionsAsText() const
{
	unsigned char *ustringval = NULL;
	unsigned int n = 0;
	BIO *bio = BIO_new(BIO_s_mem());

	X509V3_extensions_print(bio, NULL, m_impl->x509->crl->extensions, 0, 4);
	n = BIO_get_mem_data(bio, &ustringval);

	std::string extText = std::string((const char*)ustringval, n);
	BIO_free(bio);

	return extText;
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

	std::vector<std::string> r = checkRevocationData(m_impl->revocationData);
	if(!r.empty())
	{
		LOGIT_DEBUG(r[0]);
		return false;
	}
	return true;
}

std::vector<std::string>
CRLData::verify() const
{
	std::vector<std::string> result;

	if(m_impl->version < 1 || m_impl->version > 2)
	{
		result.push_back(str::form("invalid version: %d", m_impl->version));
	}
	if(m_impl->lastUpdate == 0)
	{
		result.push_back(str::form("invalid lastUpdate: %ld", m_impl->lastUpdate));
	}
	if(m_impl->nextUpdate <= m_impl->lastUpdate)
	{
		result.push_back(str::form("invalid nextUpdate: %ld", m_impl->nextUpdate));
	}
	appendArray(result, m_impl->issuer.verify());

	appendArray(result, m_impl->extensions.verify());
	appendArray(result, checkRevocationData(m_impl->revocationData));

	LOGIT_DEBUG_STRINGARRAY("CRLData::verify()", result);

	return result;
}

std::vector<std::string>
CRLData::dump() const
{
	std::vector<std::string> result;
	result.push_back("CRLData::dump()");

	result.push_back("Version = " + str::numstring(m_impl->version));
	result.push_back("Fingerprint = " + m_impl->fingerprint);
	result.push_back("last Update = " + str::numstring(m_impl->lastUpdate));
	result.push_back("next Update = " + str::numstring(m_impl->nextUpdate));
	appendArray(result, m_impl->issuer.dump());
	result.push_back("signatureAlgorithm = "+ str::numstring(m_impl->signatureAlgorithm));

	std::string s;
	for(uint i = 0; i < m_impl->signature.size(); ++i)
	{
		s += str::form( "%02x", static_cast<UInt8>(m_impl->signature[i])) + ":";
	}
	result.push_back("Signature = " + s);

	appendArray(result, m_impl->extensions.dump());

	std::map< std::string, RevocationEntry >::const_iterator it = m_impl->revocationData.begin();
	for(; it != m_impl->revocationData.end(); ++it)
	{
		result.push_back((*it).first);
		appendArray(result, ((*it).second).dump());
	}

	return result;
}

//    protected:
CRLData::CRLData()
	: m_impl(new CRLDataImpl())
{}

std::vector<std::string>
CRLData::checkRevocationData(const std::map<std::string, RevocationEntry>& rd) const
{
	std::vector<std::string> result;
	std::map<std::string, RevocationEntry>::const_iterator it = rd.begin();
	for(; it != rd.end(); ++it)
	{
		appendArray(result, ((*it).second).verify());
	}
	return result;
}

}
