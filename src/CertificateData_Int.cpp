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

  File:       CertificateData_Int.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  "CertificateData_Int.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

CertificateData_Int::CertificateData_Int()
    : CertificateData()
{
}

CertificateData_Int::CertificateData_Int(const String &caName)
    : CertificateData()
{
}

CertificateData_Int::CertificateData_Int(const String &caName,
                                         const String &certificateName)
    : CertificateData()
{
}

CertificateData_Int::~CertificateData_Int()
{
}


void
CertificateData_Int::setVersion(blocxx::UInt32 v)
{
    version = v;
}

void
CertificateData_Int::setSerial(const String& serial)
{
    this->serial = serial;
}

void
CertificateData_Int::setCertifiyPeriode(time_t start, time_t end)
{
    notBefore = start;
    notAfter  = end;
}

void
CertificateData_Int::setIssuerDN(const DNObject& issuer)
{
    this->issuer = issuer;
}

void
CertificateData_Int::setSubjectDN(const DNObject& subject)
{
    this->subject = subject;
}

void
CertificateData_Int::setKeysize(blocxx::UInt32 size)
{
    keysize = size;
}

void
CertificateData_Int::setPublicKeyAlgorithm(KeyAlg pubKeyAlg)
{
    pubkeyAlgorithm = pubKeyAlg;
}

void
CertificateData_Int::setPublicKey(const ByteArray derPublicKey)
{
    publicKey = derPublicKey;
}

void
CertificateData_Int::setSignatureAlgorithm(SigAlg sigAlg)
{
    signatureAlgorithm = sigAlg;
}

void
CertificateData_Int::setSignature(const String& sig)
{
    signature = sig;
}

void
CertificateData_Int::setExtensions(const X509v3CertificateExtensions& ext)
{
    extensions = ext;
}

//    private:
CertificateData_Int::CertificateData_Int(const CertificateData_Int& data)
    : CertificateData(data)
{
}

CertificateData_Int&
CertificateData_Int::operator=(const CertificateData_Int& data)
{
    return *this;
}
