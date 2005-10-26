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
    : serial(0), revocationDate(0), revocationReason(CRLReason())
{
}

RevocationEntry::RevocationEntry(const RevocationEntry& entry)
    : serial(entry.serial), revocationDate(entry.revocationDate),
      revocationReason(entry.revocationReason)
{}

RevocationEntry::~RevocationEntry()
{}

RevocationEntry& 
RevocationEntry::operator=(const RevocationEntry& entry)
{
    if(this == &entry) return *this;
    
    serial           = entry.serial;
    revocationDate   = entry.revocationDate;
    revocationReason = entry.revocationReason;
    
    return *this;
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

bool
RevocationEntry::valid() const
{
    if(!initHexCheck().isValid(serial)) {
        LOGIT_DEBUG("invalid serial: "<< serial);
        return false;
    }
    return revocationReason.valid();
}

blocxx::StringArray
RevocationEntry::verify() const
{
    StringArray result;
    
    if(!initHexCheck().isValid(serial)) {
        result.append(Format("invalid serial: %1", serial).toString());
    }
    result.appendArray(revocationReason.verify());

    LOGIT_DEBUG_STRINGARRAY("RevocationEntry::verify()", result);
    
    return result;
}

blocxx::StringArray
RevocationEntry::dump() const
{
    StringArray result;
    result.append("RevocationEntry::dump()");

    result.append("Serial = " + serial);
    result.append("revocation Date = " + String(revocationDate));
    result.appendArray(revocationReason.dump());

    return result;
}

// ##################################################################

CRLData::CRLData(const CRLData& data)
    : version(data.version), lastUpdate(data.lastUpdate),
      nextUpdate(data.nextUpdate), issuer(data.issuer),
      signatureAlgorithm(data.signatureAlgorithm), signature(data.signature),
      extensions(data.extensions), revocationData(data.revocationData)
{
}

CRLData::~CRLData()
{
}

CRLData& 
CRLData::operator=(const CRLData& data)
{
    if(this == &data) return *this;

    version            = data.version;
    lastUpdate         = data.lastUpdate;
    nextUpdate         = data.nextUpdate;
    issuer             = data.issuer;
    signatureAlgorithm = data.signatureAlgorithm;
    signature          = data.signature;
    extensions         = data.extensions;
    revocationData     = data.revocationData;

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

ByteBuffer
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
    if(revocationData.find(oid) != revocationData.end()) {

        return (*(revocationData.find(oid))).second;
    }
    LOGIT_ERROR("Entry not found: " << oid);
    BLOCXX_THROW(limal::ValueException, "Entry not found");
}

bool
CRLData::valid() const
{
    if(version < 1 || version > 2) {
        LOGIT_DEBUG("invalid version: " << version);
        return false;
    }
    if(lastUpdate == 0) {
        LOGIT_DEBUG("invalid lastUpdate:" << lastUpdate);
        return false;
    }
    if(nextUpdate <= lastUpdate) {
        LOGIT_DEBUG("invalid nextUpdate:" << nextUpdate);
        return false;
    }
    if(!issuer.valid())  return false;

    if(!extensions.valid()) return false;

    StringArray r = checkRevocationData(revocationData);
    if(!r.empty()) {
        LOGIT_DEBUG(r[0]);
        return false;
    }
    return true;
}

blocxx::StringArray
CRLData::verify() const
{
    StringArray result;
    
    if(version < 1 || version > 2) {
        result.append(Format("invalid version: %1", version).toString());
    }
    if(lastUpdate == 0) {
        result.append(Format("invalid lastUpdate: %1", lastUpdate).toString());
    }
    if(nextUpdate <= lastUpdate) {
        result.append(Format("invalid nextUpdate: %1", nextUpdate).toString());
    }
    result.appendArray(issuer.verify());

    result.appendArray(extensions.verify());
    result.appendArray(checkRevocationData(revocationData));

    LOGIT_DEBUG_STRINGARRAY("CRLData::verify()", result);
    
    return result;
}

blocxx::StringArray
CRLData::dump() const
{
    StringArray result;
    result.append("CRLData::dump()");

    result.append("Version = " + String(version));
    result.append("last Update = " + String(lastUpdate));
    result.append("next Update = " + String(nextUpdate));
    result.appendArray(issuer.dump());
    result.append("signatureAlgorithm = "+ String(signatureAlgorithm));

    String s;
    for(uint i = 0; i < signature.size(); ++i) {
        String d;
        d.format("%02x:", (UInt8)signature[i]);
        s += d;
    }
    result.append("Signature = " + s);

    result.appendArray(extensions.dump());

    blocxx::Map< String, RevocationEntry >::const_iterator it = revocationData.begin();
    for(; it != revocationData.end(); ++it) {
        result.append((*it).first);
        result.appendArray(((*it).second).dump());
    }

    return result;
}

//    protected:
CRLData::CRLData()
    : version(0), lastUpdate(0),
      nextUpdate(0), issuer(DNObject()),
      signatureAlgorithm(SHA1RSA), signature(ByteBuffer()),
      extensions(X509v3CRLExtensions_Priv()), 
      revocationData(blocxx::Map<String, RevocationEntry>())
{
}

StringArray
CRLData::checkRevocationData(const blocxx::Map<String, RevocationEntry>& rd) const
{
    StringArray result;
    blocxx::Map<String, RevocationEntry>::const_iterator it = rd.begin();
    for(; it != rd.end(); ++it) {
        result.appendArray(((*it).second).verify());
    }
    return result;
}

}
}
