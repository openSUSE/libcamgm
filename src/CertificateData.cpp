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
#include  "X509v3CertificateExtensions_Int.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

CertificateData::CertificateData(const CertificateData& data)
    : extensions(data.extensions)
{
}

CertificateData::~CertificateData()
{
}


CertificateData& 
CertificateData::operator=(const CertificateData& data)
{
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
    return String();
}

blocxx::String
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

                

//    protected
CertificateData::CertificateData()
    : extensions(X509v3CertificateExtensions_Int())
{
}


