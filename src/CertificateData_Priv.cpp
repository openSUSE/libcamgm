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

  File:       CertificateData_Priv.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  "CertificateData_Priv.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

CertificateData_Priv::CertificateData_Priv()
    : CertificateData()
{
}

CertificateData_Priv::CertificateData_Priv(const String &caName)
    : CertificateData()
{
}

CertificateData_Priv::CertificateData_Priv(const String &caName,
                                         const String &certificateName)
    : CertificateData()
{
}

CertificateData_Priv::~CertificateData_Priv()
{
}


void
CertificateData_Priv::setVersion(blocxx::UInt32 v)
{
    version = v;
}

void
CertificateData_Priv::setSerial(const String& serial)
{
    this->serial = serial;
}

void
CertificateData_Priv::setCertifiyPeriode(time_t start, time_t end)
{
    notBefore = start;
    notAfter  = end;
}

void
CertificateData_Priv::setIssuerDN(const DNObject& issuer)
{
    this->issuer = issuer;
}

void
CertificateData_Priv::setSubjectDN(const DNObject& subject)
{
    this->subject = subject;
}

void
CertificateData_Priv::setKeysize(blocxx::UInt32 size)
{
    keysize = size;
}

void
CertificateData_Priv::setPublicKeyAlgorithm(KeyAlg pubKeyAlg)
{
    pubkeyAlgorithm = pubKeyAlg;
}

void
CertificateData_Priv::setPublicKey(const ByteArray derPublicKey)
{
    publicKey = derPublicKey;
}

void
CertificateData_Priv::setSignatureAlgorithm(SigAlg sigAlg)
{
    signatureAlgorithm = sigAlg;
}

void
CertificateData_Priv::setSignature(const String& sig)
{
    signature = sig;
}

void
CertificateData_Priv::setExtensions(const X509v3CertificateExtensions& ext)
{
    extensions = ext;
}

//    private:
CertificateData_Priv::CertificateData_Priv(const CertificateData_Priv& data)
    : CertificateData(data)
{
}

CertificateData_Priv&
CertificateData_Priv::operator=(const CertificateData_Priv& data)
{
    return *this;
}
