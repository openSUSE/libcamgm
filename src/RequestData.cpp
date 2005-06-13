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

  File:       RequestData.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/RequestData.hpp>

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;


RequestData::RequestData(const RequestData& data)
{
}

RequestData::~RequestData()
{
}

RequestData&
RequestData::operator=(const RequestData& data)
{
    return *this;
}

blocxx::UInt32
RequestData::getVersion() const
{
    return version;
}

blocxx::UInt32
RequestData::getKeysize() const
{
    return keysize;
}

DNObject
RequestData::getSubject() const
{
    return subject;
}

KeyAlg
RequestData::getKeyAlgorithm() const
{
    return pubkeyAlgorithm;
}

ByteArray
RequestData::getPublicKey() const
{
    return publicKey;
}

SigAlg
RequestData::getSignatureAlgorithm() const
{
    return signatureAlgorithm;
}

blocxx::String
RequestData::getSignature() const
{
    return signature;
}

blocxx::String
RequestData::getFingerprint() const
{
    return String();
}

X509v3RequestExtensions
RequestData::getExtensions() const
{
    return extensions;
}

blocxx::String
RequestData::getChallengePassword() const
{
    return challengePassword;
}

blocxx::String
RequestData::getUnstructuredName() const
{
    return unstructuredName;
}


//    protected:
RequestData::RequestData()
{
}

