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

  File:       CertificateData.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/CertificateData.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

#include  "Utils.hpp"
#include  "X509v3CertificateExtensions_Priv.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

CertificateData::CertificateData(const CertificateData& data)
    : version(data.version), serial(data.serial), 
      notBefore(data.notBefore), notAfter(data.notAfter),
      issuer(data.issuer), subject(data.subject),
      keysize(data.keysize), pubkeyAlgorithm(data.pubkeyAlgorithm),
      publicKey(data.publicKey), signatureAlgorithm(data.signatureAlgorithm),
      signature(data.signature), extensions(data.extensions)
{}

CertificateData::~CertificateData()
{}


CertificateData& 
CertificateData::operator=(const CertificateData& data)
{
    if(this == &data) return *this;

    version            = data.version;
    serial             = data.serial;
    notBefore          = data.notBefore;
    notAfter           = data.notAfter;
    issuer             = data.issuer;
    subject            = data.subject;
    keysize            = data.keysize;
    pubkeyAlgorithm    = data.pubkeyAlgorithm;
    publicKey          = data.publicKey;
    signatureAlgorithm = data.signatureAlgorithm;
    signature          = data.signature;
    extensions         = data.extensions;

    return *this;
}

blocxx::UInt32 
CertificateData::getVersion() const
{
    return version;
}

blocxx::String
CertificateData::getSerial() const
{
    return serial;
}

time_t
CertificateData::getStartDate() const
{
    return notBefore;
}

time_t
CertificateData::getEndDate() const
{
    return notAfter;
}

DNObject
CertificateData::getIssuerDN() const
{
    return issuer;
}

DNObject
CertificateData::getSubjectDN() const
{
    return subject;
}

blocxx::UInt32
CertificateData::getKeysize() const
{
    return keysize;
}

KeyAlg
CertificateData::getPublicKeyAlgorithm() const
{
    return pubkeyAlgorithm;
}

blocxx::String
CertificateData::getPublicKeyAlgorithmAsString() const
{
    switch(pubkeyAlgorithm) {
    case RSA:
        return "RSA";
        break;
    case DSA:
        return "DSA";
        break;
    case DH:
        return "DH";
        break;
    }
    return String();
}

ByteArray
CertificateData::getPublicKey() const
{
    return publicKey;
}

SigAlg
CertificateData::getSignatureAlgorithm() const
{
    return signatureAlgorithm;
}

blocxx::String
CertificateData::getSignatureAlgorithmAsString() const
{
    switch(signatureAlgorithm) {
    case SHA1RSA:
        return "SHA1RSA";
        break;
    case MD5RSA:
        return "MD5RSA";
        break;
    case SHA1DSA:
        return "SHA1DSA";
        break;
    }
    return String();
}

ByteArray
CertificateData::getSignature() const
{
    return signature;
}

blocxx::String
CertificateData::getFingerprint() const
{
    return String();
}

X509v3CertificateExtensions
CertificateData::getExtensions() const
{
    return extensions;
}

bool
CertificateData::valid() const
{
    if(version < 1 || version > 3) {
        LOGIT_DEBUG("invalid version:" << version);
        return false;
    }

    if(!initHexCheck().isValid(serial)) {
        LOGIT_DEBUG("invalid serial:" << serial);
        return false;
    }

    if(notBefore == 0) {
        LOGIT_DEBUG("invalid notBefore:" << notBefore);
        return false;
    }
    if(notAfter <= notBefore) {
        LOGIT_DEBUG("invalid notAfter:" << notAfter);
        return false;
    }
    if(!issuer.valid())  return false;
    if(!subject.valid()) return false;

    // keysize ?

    if(publicKey.empty()) {
        LOGIT_DEBUG("invalid publicKey");
        return false;
    }

    /*
      if(!initHexCheck().isValid(signature)) {
      LOGIT_DEBUG("invalid signature:" << signature);
      return false;
      }
    */
    if(!extensions.valid()) return false;
    
    return true;
}

blocxx::StringArray
CertificateData::verify() const
{
    StringArray result;

    if(version < 1 || version > 3) {
        result.append(Format("invalid version: %1", version).toString());
    }

    if(!initHexCheck().isValid(serial)) {
        result.append(Format("invalid serial: %1", serial).toString());
    }

    if(notBefore == 0) {
        result.append(Format("invalid notBefore: %1", notBefore).toString());
    }
    if(notAfter <= notBefore) {
        result.append(Format("invalid notAfter: %1", notAfter).toString());
    }
    result.appendArray(issuer.verify());
    result.appendArray(subject.verify());

    // keysize ?

    if(publicKey.empty()) {
        result.append("invalid publicKey");
    }

    /*
      if(!initHexCheck().isValid(signature)) {
      result.append(Format("invalid signature: %1", signature).toString());
      }
    */
    result.appendArray(extensions.verify());
    
    LOGIT_DEBUG_STRINGARRAY("CertificateData::verify()", result);

    return result;
}
                
blocxx::StringArray
CertificateData::dump() const
{
    StringArray result;
    result.append("CertificateData::dump()");

    result.append("Version = " + String(version));
    result.append("Serial = " + String(serial));
    result.append("notBefore = " + String(notBefore));
    result.append("notAfter = " + String(notAfter));
    result.appendArray(issuer.dump());
    result.appendArray(subject.dump());
    result.append("Keysize = " + String(keysize));
    result.append("public key algorithm = " + String(pubkeyAlgorithm));

    String pk;
    ByteArray::const_iterator it = publicKey.begin();
    for(; it != publicKey.end(); ++it) {
        pk += *it + " ";
    }
    result.append("public Key = " + pk);
    result.append("signatureAlgorithm = "+ String(signatureAlgorithm));

    String s;
    for(int i = 0; i < signature.size(); ++i) {
        String d;
        d.format("%02x:", signature[i]);
        s += d;
    }

    result.append("Signature = " + s);
    result.appendArray(extensions.dump());

    return result;
}

//    protected
CertificateData::CertificateData()
    : version(0), serial(0), 
      notBefore(0), notAfter(0),
      issuer(DNObject()), subject(DNObject()),
      keysize(2048), pubkeyAlgorithm(RSA),
      publicKey(ByteArray()), signatureAlgorithm(SHA1RSA),
      signature(ByteArray()), extensions(X509v3CertificateExtensions_Priv())
{
}


