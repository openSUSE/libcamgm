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
#include  "X509v3CRLExtensions_Priv.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;


RevocationEntry::RevocationEntry()
{
}

RevocationEntry::RevocationEntry(const String&    serial, 
                                 time_t           revokeDate,
                                 const CRLReason& reason)
{
}

RevocationEntry::RevocationEntry(const RevocationEntry& entry)
{
}

RevocationEntry::~RevocationEntry()
{
}

RevocationEntry& 
RevocationEntry::operator=(const RevocationEntry& entry)
{
    return *this;
}


void
RevocationEntry::setSerial(const String& serial)
{
    this->serial = serial;
}

void
RevocationEntry::setRevocationDate(time_t date)
{
    revocationDate = date;
}

void
RevocationEntry::setReason(const CRLReason& reason)
{
    revocationReason = reason;
}

blocxx::String
RevocationEntry::getSerial() const
{
    return serial;
}

time_t
RevocationEntry::getRevocationDate() const
{
    return revocationDate;
}

CRLReason
RevocationEntry::getReason() const
{
    return revocationReason;
}


// ##################################################################

CRLData::CRLData(const CRLData& data)
    : extensions(data.extensions)
{
}

CRLData::~CRLData()
{
}

CRLData& 
CRLData::operator=(const CRLData& data)
{
    return *this;
}

blocxx::Int32
CRLData::getVersion() const
{
    return version;
}

time_t
CRLData::getLastUpdateDate() const
{
    return lastUpdate;
}

time_t
CRLData::getNextUpdateDate() const
{
    return nextUpdate;
}

DNObject
CRLData::getIssuerDN() const
{
    return issuer;
}

SigAlg
CRLData::getSignatureAlgorithm() const
{
    return signatureAlgorithm;
}

blocxx::String
CRLData::getSignatureAlgorithmAsString() const
{
    return String();
}

blocxx::String
CRLData::getSignature() const
{
    return signature;
}

X509v3CRLExtensions
CRLData::getExtensions() const
{
    return extensions;
}

blocxx::Map<blocxx::String, RevocationEntry>
CRLData::getRevocationData() const
{
    return revocationData;
}

RevocationEntry
CRLData::getRevocationEntry(const String& oid)
{
    return RevocationEntry();
}


//    protected:
CRLData::CRLData()
    : extensions(X509v3CRLExtensions_Priv())
{
}

