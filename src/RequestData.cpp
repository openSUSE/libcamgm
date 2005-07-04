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
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

#include  "Utils.hpp"
#include  "X509v3RequestExtensions_Priv.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;


RequestData::RequestData(const RequestData& data)
    : version(data.version),
      subject(data.subject),
      keysize(data.keysize),
      pubkeyAlgorithm(data.pubkeyAlgorithm),
      publicKey(data.publicKey),
      signatureAlgorithm(data.signatureAlgorithm),
      signature(data.signature),
      extensions(data.extensions),
      challengePassword(data.challengePassword), 
      unstructuredName(data.unstructuredName)
{
}

RequestData::~RequestData()
{
}

RequestData&
RequestData::operator=(const RequestData& data)
{
    if(this == &data) return *this;

    version            = data.version;
    subject            = data.subject;
    keysize            = data.keysize;
    pubkeyAlgorithm    = data.pubkeyAlgorithm;
    publicKey          = data.publicKey;
    signatureAlgorithm = data.signatureAlgorithm;
    signature          = data.signature;
    extensions         = data.extensions;
    challengePassword  = data.challengePassword;
    unstructuredName   = data.unstructuredName;

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

bool
RequestData::valid() const
{
    if(version < 1 || version > 1) {
        LOGIT_DEBUG("invalid version:" << version);
        return false;
    }

    if(!subject.valid()) return false;

    // keysize ?

    if(publicKey.empty()) {
        LOGIT_DEBUG("invalid publicKey");
        return false;
    }

    if(!initHexCheck().isValid(signature)) {
        LOGIT_DEBUG("invalid signature:" << signature);
        return false;
    }
    if(!extensions.valid()) return false;

    return true;
}

blocxx::StringArray
RequestData::verify() const
{
    StringArray result;

    if(version < 1 || version > 1) {
        result.append(Format("invalid version: %1", version).toString());
    }

    result.appendArray(subject.verify());

    // keysize ?

    if(publicKey.empty()) {
        result.append("invalid publicKey");
    }

    if(!initHexCheck().isValid(signature)) {
        result.append(Format("invalid signature: %1", signature).toString());
    }
    result.appendArray(extensions.verify());

    LOGIT_DEBUG_STRINGARRAY("CertificateData::verify()", result);

    return result;
}

//    protected:
RequestData::RequestData()
    : version(0),
      subject(DNObject()),
      keysize(0),
      pubkeyAlgorithm(RSA),
      publicKey(ByteArray()),
      signatureAlgorithm(SHA1RSA),
      signature(""),
      extensions(X509v3RequestExtensions_Priv()),
      challengePassword(""), 
      unstructuredName("")
{
}

