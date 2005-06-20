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

  File:       CRLData_Int.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  "CRLData_Int.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

CRLData_Int::CRLData_Int()
    : CRLData()
{
}

CRLData_Int::CRLData_Int(const String &caName)
    : CRLData()
{
}

CRLData_Int::~CRLData_Int()
{
}

void
CRLData_Int::setVersion(blocxx::Int32 version)
{
    this->version = version;
}

void
CRLData_Int::setValidityPeriod(time_t last,
                               time_t next)
{
    lastUpdate = last;
    nextUpdate = next;
}

void
CRLData_Int::setIssuerDN(const DNObject& issuer)
{
    this->issuer = issuer;
}

void
CRLData_Int::setSignatureAlgorithm(SigAlg sigAlg)
{
    signatureAlgorithm = sigAlg;
}

void
CRLData_Int::setSignature(const String& sig)
{
    signature = sig;
}

void
CRLData_Int::setExtensions(const X509v3CRLExtensions& ext)
{
    extensions = ext;
}

void
CRLData_Int::setRevocationData(const blocxx::Map<String, RevocationEntry>& data)
{
    revocationData = data;
}

void
CRLData_Int::addRevocationEntry(const String& oid,
                                const RevocationEntry& entry)
{
}

void
CRLData_Int::setRevocationEntry(const String& oid,
                                const RevocationEntry& entry)
{
}

void
CRLData_Int::deleteRevocationEntry(const String& oid)
{
}


//  private:
CRLData_Int::CRLData_Int(const CRLData_Int& data)
    : CRLData()
{
}

CRLData_Int&
CRLData_Int::operator=(const CRLData_Int& data)
{
    return *this;
}
