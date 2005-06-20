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

  File:       RequestData_Priv.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  "RequestData_Priv.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

RequestData_Priv::RequestData_Priv()
    : RequestData()
{
}

RequestData_Priv::RequestData_Priv(const String& caName,
                                 const String& requestName)
    : RequestData()
{
}

RequestData_Priv::~RequestData_Priv()
{
}


void
RequestData_Priv::setVersion(blocxx::UInt32 v)
{
    version = v;
}

void
RequestData_Priv::setKeysize(blocxx::UInt32 size)
{
    keysize = size;
}

void
RequestData_Priv::setSubject(const DNObject dn)
{
    subject = dn;
}

void
RequestData_Priv::setKeyAlgorithm(KeyAlg alg)
{
    pubkeyAlgorithm = alg; 
}

void
RequestData_Priv::setPublicKey(const ByteArray key)
{
    publicKey = key;
}

void
RequestData_Priv::setSignatureAlgorithm(SigAlg alg)
{
    signatureAlgorithm = alg;
}

void
RequestData_Priv::setSignature(const String &sig)
{
    signature = sig;
}

void
RequestData_Priv::setExtensions(const X509v3RequestExtensions &ext)
{
    extensions = ext;
}

void
RequestData_Priv::setChallengePassword(const String &passwd)
{
    challengePassword = passwd;
}

void
RequestData_Priv::setUnstructuredName(const String &name)
{
    unstructuredName = name;
}


//    private:
RequestData_Priv::RequestData_Priv(const RequestData_Priv& data)
    : RequestData(data)
{
}

RequestData_Priv&
RequestData_Priv::operator=(const RequestData_Priv& data)
{
    return *this;
}
