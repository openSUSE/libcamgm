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
    if(!initHexCheck().isValid(serial)) {
        LOGIT_ERROR("invalid serial: " << serial);
        BLOCXX_THROW(limal::ValueException, Format("invalid serial: %1", serial).c_str());
    }
    StringArray r = reason.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    this->serial     = serial;
    revocationDate   = revokeDate;
    revocationReason = reason;
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
    if(!initHexCheck().isValid(serial)) {
        LOGIT_ERROR("invalid serial: " << serial);
        BLOCXX_THROW(limal::ValueException, Format("invalid serial: %1", serial).c_str());
    }
    this->serial = serial;
}

void
RevocationEntry_Priv::setRevocationDate(time_t date)
{
    revocationDate = date;
}

void
RevocationEntry_Priv::setReason(const CRLReason& reason)
{
    if(!reason.valid()) {
        LOGIT_ERROR("invalid CRL reason");
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

CRLData_Priv::CRLData_Priv(const CRLData_Priv& data)
    : CRLData(data)
{
}

CRLData_Priv::~CRLData_Priv()
{}

void
CRLData_Priv::setVersion(blocxx::Int32 version)
{
    this->version = version;
}

void
CRLData_Priv::setValidityPeriod(time_t last,
                                time_t next)
{
    lastUpdate = last;
    nextUpdate = next;
}

void
CRLData_Priv::setIssuerDN(const DNObject& issuer)
{
    StringArray r = issuer.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
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
    if(!initHexCheck().isValid(sig)) {
        LOGIT_ERROR("invalid signature: " << sig);
        BLOCXX_THROW(limal::ValueException, Format("invalid signature: %1", sig).c_str());
    }
    signature = sig;
}

void
CRLData_Priv::setExtensions(const X509v3CRLExtensions& ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    extensions = ext;
}

void
CRLData_Priv::setRevocationData(const blocxx::Map<String, RevocationEntry>& data)
{
    StringArray r = checkRevocationData(data);
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    revocationData = data;
}


//  private:


CRLData_Priv&
CRLData_Priv::operator=(const CRLData_Priv& data)
{
    if(this == &data) return *this;

    CRLData::operator=(data);

    return *this;
}
