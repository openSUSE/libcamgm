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
#include  "X509v3CRLExtensions_Int.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;


RevokationEntry::RevokationEntry()
{
}

RevokationEntry::RevokationEntry(const String&    serial, 
                                 time_t           revokeDate,
                                 const CRLReason& reason)
{
}

RevokationEntry::RevokationEntry(const RevokationEntry& entry)
{
}

RevokationEntry::~RevokationEntry()
{
}

RevokationEntry& 
RevokationEntry::operator=(const RevokationEntry& entry)
{
    return *this;
}


void
RevokationEntry::setSerial(const String& serial)
{
    this->serial = serial;
}

void
RevokationEntry::setRevokationDate(time_t date)
{
    revokationDate = date;
}

void
RevokationEntry::setReason(const CRLReason& reason)
{
    revokationReason = reason;
}

blocxx::String
RevokationEntry::getSerial() const
{
    return serial;
}

time_t
RevokationEntry::getRevokationDate() const
{
    return revokationDate;
}

CRLReason
RevokationEntry::getReason() const
{
    return revokationReason;
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

blocxx::Map<blocxx::String, RevokationEntry>
CRLData::getRevokationData() const
{
    return revokationData;
}

RevokationEntry
CRLData::getRevokationEntry(const String& oid)
{
    return RevokationEntry();
}


//    protected:
CRLData::CRLData()
    : extensions(X509v3CRLExtensions_Int())
{
}

