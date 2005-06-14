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

  File:       RequestData_Int.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  "RequestData_Int.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

RequestData_Int::RequestData_Int()
    : RequestData()
{
}

RequestData_Int::RequestData_Int(const String& caName,
                                 const String& requestName)
    : RequestData()
{
}

RequestData_Int::~RequestData_Int()
{
}


void
RequestData_Int::setVersion(blocxx::UInt32 v)
{
    version = v;
}

void
RequestData_Int::setKeysize(blocxx::UInt32 size)
{
    keysize = size;
}

void
RequestData_Int::setSubject(const DNObject dn)
{
    subject = dn;
}

void
RequestData_Int::setKeyAlgorithm(KeyAlg alg)
{
    pubkeyAlgorithm = alg; 
}

void
RequestData_Int::setPublicKey(const ByteArray key)
{
    publicKey = key;
}

void
RequestData_Int::setSignatureAlgorithm(SigAlg alg)
{
    signatureAlgorithm = alg;
}

void
RequestData_Int::setSignature(const String &sig)
{
    signature = sig;
}

void
RequestData_Int::setExtensions(const X509v3RequestExtensions &ext)
{
    extensions = ext;
}

void
RequestData_Int::setChallengePassword(const String &passwd)
{
    challengePassword = passwd;
}

void
RequestData_Int::setUnstructuredName(const String &name)
{
    unstructuredName = name;
}


//    private:
RequestData_Int::RequestData_Int(const RequestData_Int& data)
    : RequestData(data)
{
}

RequestData_Int&
RequestData_Int::operator=(const RequestData_Int& data)
{
    return *this;
}
