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

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
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

ByteBuffer
RequestData::getPublicKey() const
{
    return publicKey;
}

SigAlg
RequestData::getSignatureAlgorithm() const
{
    return signatureAlgorithm;
}

ByteBuffer
RequestData::getSignature() const
{
    return signature;
}

blocxx::String
RequestData::getFingerprint() const
{
    return String();
}

X509v3RequestExts
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

    result.appendArray(extensions.verify());

    LOGIT_DEBUG_STRINGARRAY("CertificateData::verify()", result);

    return result;
}

blocxx::StringArray
RequestData::dump() const
{
    StringArray result;
    result.append("RequestData::dump()");
    
    result.append("Version = " + String(version));
    result.appendArray(subject.dump());
    result.append("Keysize = " + String(keysize));
    result.append("pubkeyAlgorithm = " + String(pubkeyAlgorithm));
    
    String pk;
    for(size_t i = 0; i < publicKey.size(); ++i) {
        String s;
        s.format("%02x", (UInt8)publicKey[i]);
        pk += s + ":";
    }
    result.append("public Key = " + pk);
    
    result.append("signatureAlgorithm = "+ String(signatureAlgorithm));

    String s;
    for(uint i = 0; i < signature.size(); ++i) {
        String d;
        d.format("%02x:", (UInt8)signature[i]);
        s += d;
    }

    result.append("Signature = " + s);

    result.appendArray(extensions.dump());
    result.append("Challenge Password = " + challengePassword);
    result.append("Unstructured Name = " + unstructuredName);
    
    return result;
}


//    protected:
RequestData::RequestData()
    : version(0),
      subject(DNObject()),
      keysize(0),
      pubkeyAlgorithm(E_RSA),
      publicKey(ByteBuffer()),
      signatureAlgorithm(E_SHA1RSA),
      signature(ByteBuffer()),
      extensions(X509v3RequestExts_Priv()),
      challengePassword(""), 
      unstructuredName("")
{
}

}
}
