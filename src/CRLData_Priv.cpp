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

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

CRLData_Priv::CRLData_Priv()
    : CRLData()
{
}

CRLData_Priv::CRLData_Priv(const String &caName)
    : CRLData()
{
}

CRLData_Priv::~CRLData_Priv()
{
}

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
    signature = sig;
}

void
CRLData_Priv::setExtensions(const X509v3CRLExtensions& ext)
{
    extensions = ext;
}

void
CRLData_Priv::setRevocationData(const blocxx::Map<String, RevocationEntry>& data)
{
    revocationData = data;
}

void
CRLData_Priv::addRevocationEntry(const String& oid,
                                const RevocationEntry& entry)
{
}

void
CRLData_Priv::setRevocationEntry(const String& oid,
                                const RevocationEntry& entry)
{
}

void
CRLData_Priv::deleteRevocationEntry(const String& oid)
{
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
