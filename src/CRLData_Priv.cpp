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

  File:       CRLData_Priv.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  "CRLData_Priv.hpp"
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

RevocationEntry_Priv::RevocationEntry_Priv()
    : RevocationEntry()
{}

RevocationEntry_Priv::RevocationEntry_Priv(const String&    serial, 
                                           time_t           revokeDate,
                                           const CRLReason& reason)
    : RevocationEntry()
{
    this->serial     = serial;
    revocationDate   = revokeDate;
    revocationReason = reason;

    StringArray r = this->verify();
    if(!r.empty()) {
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

RevocationEntry_Priv::RevocationEntry_Priv(const RevocationEntry_Priv& entry)
    : RevocationEntry(entry)
{}

RevocationEntry_Priv::~RevocationEntry_Priv()
{}

RevocationEntry_Priv&
RevocationEntry_Priv::operator=(const RevocationEntry_Priv& entry)
{
    if(this == &entry) return *this;
    
    RevocationEntry::operator=(entry);
    
    return *this;
}

void
RevocationEntry_Priv::setSerial(const String& serial)
{
    String oldSerial = this->serial;

    this->serial = serial;

    StringArray r = this->verify();
    if(!r.empty()) {
        this->serial = oldSerial;

        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

void
RevocationEntry_Priv::setRevocationDate(time_t date)
{
    time_t oldDate = revocationDate;

    revocationDate = date;

    StringArray r = this->verify();
    if(!r.empty()) {
        this->revocationDate = oldDate;
        
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

void
RevocationEntry_Priv::setReason(const CRLReason& reason)
{
    if(!reason.valid()) {
        BLOCXX_THROW(limal::ValueException, "invalid CRL reason");
    }
    revocationReason = reason;
}

// #############################################################################

CRLData_Priv::CRLData_Priv()
    : CRLData()
{}

CRLData_Priv::CRLData_Priv(const String &caName)
    : CRLData()
{
}

CRLData_Priv::~CRLData_Priv()
{}

void
CRLData_Priv::setVersion(blocxx::Int32 version)
{
    blocxx::Int32 oldVersion = this->version;

    this->version = version;

    StringArray r = this->verify();
    if(!r.empty()) {
        this->version = oldVersion;

        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

void
CRLData_Priv::setValidityPeriod(time_t last,
                                time_t next)
{
    time_t oldStart = lastUpdate;
    time_t oldEnd   = nextUpdate;

    lastUpdate = last;
    nextUpdate = next;

    StringArray r = this->verify();
    if(!r.empty()) {
        lastUpdate = oldStart;
        nextUpdate = oldEnd;
        
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

void
CRLData_Priv::setIssuerDN(const DNObject& issuer)
{
    StringArray r = issuer.verify();
    if(!r.empty()) {
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }    
    this->issuer = issuer;
}

void
CRLData_Priv::setSignatureAlgorithm(SigAlg sigAlg)
{
    signatureAlgorithm = sigAlg;
}

void
CRLData_Priv::setSignature(const String& sig)
{
    String oldSig = signature;

    signature = sig;

    StringArray r = this->verify();
    if(!r.empty()) {
        signature = oldSig;
        
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

void
CRLData_Priv::setExtensions(const X509v3CRLExtensions& ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }    
    extensions = ext;
}

void
CRLData_Priv::setRevocationData(const blocxx::Map<String, RevocationEntry>& data)
{
    blocxx::Map<String, RevocationEntry> oldData = revocationData;

    revocationData = data;

    StringArray r = this->verify();
    if(!r.empty()) {
        revocationData = oldData;
        
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}


//  private:
CRLData_Priv::CRLData_Priv(const CRLData_Priv& data)
    : CRLData()
{
}

CRLData_Priv&
CRLData_Priv::operator=(const CRLData_Priv& data)
{
    return *this;
}
