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

#include <limal/ca-mgm/LocalManagement.hpp>

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

#include  <blocxx/DateTime.hpp>

#include  <limal/Exception.hpp>
#include  <limal/PathInfo.hpp>

#include  "Utils.hpp"
#include  "DNObject_Priv.hpp"
#include  "X509v3CertificateExtensions_Priv.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;

CertificateData_Priv::CertificateData_Priv()
    : CertificateData()
{
}

CertificateData_Priv::CertificateData_Priv(const ByteBuffer &certificate,
                                           FormatType formatType)
    : CertificateData()
{
    BIO  *bio;
    X509 *x509 = NULL;

    unsigned char *d = (unsigned char*)certificate.data();

    if( formatType == PEM ) {

        // load the certificate into a memory bio 
        bio = BIO_new_mem_buf(d, certificate.size());

        if(!bio) {
            
            LOGIT_ERROR("Can not create a memory BIO");
            BLOCXX_THROW(limal::MemoryException, "Can not create a memory BIO");
            
        }

        // create the X509 structure
        x509 = PEM_read_bio_X509(bio, NULL, 0, NULL);
        BIO_free(bio);

    } else {

        // => DER

#if OPENSSL_VERSION_NUMBER >= 0x0090801fL        
        const unsigned char *d2 = NULL;
        d2 = (const unsigned char*)d;
#else
        unsigned char *d2 = NULL;
        d2 = d;
#endif
        
        x509 = d2i_X509(NULL, &d2, certificate.size());

        d2 = NULL;

    }

    if(x509 == NULL) {

        LOGIT_ERROR("Can not parse certificate");
        BLOCXX_THROW(limal::RuntimeException, "Can not parse certificate");

    }

    try {

        parseCertificate(x509);

    } catch(Exception &e) {

        X509_free(x509);

        BLOCXX_THROW_SUBEX(limal::SyntaxException,
                           "Error at parsing the certificate",
                           e);

    }
    
    X509_free(x509);

}

CertificateData_Priv::CertificateData_Priv(const String &certificatePath,
                                           FormatType formatType)
    : CertificateData()
{
    ByteBuffer ba = LocalManagement::readFile(certificatePath);
    
    // FIXME: I do not know if this is the right way :-)
    *this = CertificateData_Priv(ba, formatType);
}

CertificateData_Priv::CertificateData_Priv(const CertificateData_Priv& data)
    : CertificateData(data)
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
    if(!initHexCheck().isValid(serial)) {
        LOGIT_ERROR("invalid serial: " << serial);
        BLOCXX_THROW(limal::ValueException, Format("invalid serial: %1", serial).c_str());
    }
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
    StringArray r = issuer.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    this->issuer = issuer;
}

void
CertificateData_Priv::setSubjectDN(const DNObject& subject)
{
    StringArray r = subject.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
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
CertificateData_Priv::setPublicKey(const ByteBuffer derPublicKey)
{
    publicKey = derPublicKey;
}

void
CertificateData_Priv::setSignatureAlgorithm(SigAlg sigAlg)
{
    signatureAlgorithm = sigAlg;
}

void
CertificateData_Priv::setSignature(const ByteBuffer& sig)
{
    signature = sig;
}

void
CertificateData_Priv::setExtensions(const X509v3CertificateExtensions& ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    extensions = ext;
}

//    private:


CertificateData_Priv&
CertificateData_Priv::operator=(const CertificateData_Priv& data)
{
    if(this == &data) return *this;
    
    CertificateData::operator=(data);
    
    return *this;
}

void
CertificateData_Priv::parseCertificate(X509 *x509) 
{
    

    // get version
    version = X509_get_version(x509) + 1;
    
    // get serial
    //
    // convert to hexadecimal version of the serial number 
    serial.format("%02llx",
                  String(i2s_ASN1_INTEGER(NULL,X509_get_serialNumber(x509))).toUInt64());
    

    // get notBefore
    ASN1_TIME *t   = X509_get_notBefore(x509);
    char      *cbuf = new char[t->length + 1];

    memcpy(cbuf, t->data, t->length);
    cbuf[t->length] = '\0';

    String sbuf = String(cbuf);
    delete [] cbuf;

    PerlRegEx r("^(\\d\\d)(\\d\\d)(\\d\\d)(\\d\\d)(\\d\\d)(\\d\\d)Z$");
    StringArray sa = r.capture(sbuf);
    
    if(sa.size() != 7) {

        LOGIT_ERROR("Can not parse date: " << sbuf);
        BLOCXX_THROW(limal::RuntimeException, 
                     Format("Can not parse date: %1", sbuf).c_str());

    }
    int year = 1970;
    if(sa[1].toInt() >= 70 && sa[1].toInt() <= 99) {
        year = sa[1].toInt() + 1900;
    } else {
        year = sa[1].toInt() + 2000;
    }

    DateTime dt(year, sa[2].toInt(), sa[3].toInt(),
                sa[4].toInt(), sa[5].toInt(), sa[6].toInt(),
                0, DateTime::E_UTC_TIME);
    notBefore = dt.get();

    // get notAfter
    t    = X509_get_notAfter(x509);
    cbuf = new char[t->length + 1];

    memcpy(cbuf, t->data, t->length);
    cbuf[t->length] = '\0';

    sbuf = String(cbuf);
    delete [] cbuf;

    sa = r.capture(sbuf);
    
    if(sa.size() != 7) {

        LOGIT_ERROR("Can not parse date: " << sbuf);
        BLOCXX_THROW(limal::RuntimeException, 
                     Format("Can not parse date: %1", sbuf).c_str());

    }
    year = 1970;
    if(sa[1].toInt() >= 70 && sa[1].toInt() <= 99) {
        year = sa[1].toInt() + 1900;
    } else {
        year = sa[1].toInt() + 2000;
    }
    
    dt = DateTime(year, sa[2].toInt(), sa[3].toInt(),
                  sa[4].toInt(), sa[5].toInt(), sa[6].toInt(),
                  0, DateTime::E_UTC_TIME);
    notAfter = dt.get();
    
    // get issuer
    
    issuer = DNObject_Priv(X509_get_issuer_name(x509));
    
    // get subject
    
    subject = DNObject_Priv(X509_get_subject_name(x509));
    
    // get public key
    EVP_PKEY *pkey = X509_get_pubkey(x509);
    
    if(pkey == NULL) {
        
        LOGIT_ERROR("Unable to get public key");
        BLOCXX_THROW(limal::RuntimeException, "Unable to get public key");
        
    }
    
    if(pkey->type == EVP_PKEY_RSA) {
        
        rsa_st *rsa = EVP_PKEY_get1_RSA(pkey);
        
        if(!rsa) {
            LOGIT_ERROR("could not get RSA key");
            BLOCXX_THROW(limal::RuntimeException, "could not get RSA key");
        }
        
        unsigned char *y = NULL;
        
        int len  = i2d_RSA_PUBKEY(rsa, &y);

        publicKey = ByteBuffer((char*)y, len);
        
        free(y); // ??
        RSA_free(rsa);
            
    } else {
        // unsupported type
        
        EVP_PKEY_free(pkey);
        
        LOGIT_ERROR("Unsupported public key type");
        BLOCXX_THROW(limal::RuntimeException, "Unsupported public key type");
        
    }

    // get keysize
    if (pkey->type == EVP_PKEY_RSA) {
        keysize = BN_num_bits(pkey->pkey.rsa->n);
    }
    // no need for else; unsupported key type was fetched before


    // get pubkeyAlgorithm

    if(pkey->type == EVP_PKEY_RSA || 
       pkey->type == EVP_PKEY_RSA2 ) {

        pubkeyAlgorithm = RSA;

    } else if(pkey->type == EVP_PKEY_DSA  || 
              pkey->type == EVP_PKEY_DSA1 || 
              pkey->type == EVP_PKEY_DSA2 ||
              pkey->type == EVP_PKEY_DSA3 ||
              pkey->type == EVP_PKEY_DSA4  ) {

        pubkeyAlgorithm = DSA;

    } else if(pkey->type == EVP_PKEY_DH ) {

        pubkeyAlgorithm = DH;

    } else {

        EVP_PKEY_free(pkey);

        LOGIT_ERROR("Unsupported public key algorithm");
        BLOCXX_THROW(limal::RuntimeException, "Unsupported public key algorithm");
        
    }

    // get signatureAlgorithm

    BIO *bio = BIO_new(BIO_s_mem());
    i2a_ASN1_OBJECT(bio, x509->cert_info->signature->algorithm);
    int n = BIO_get_mem_data(bio, &cbuf);

    sbuf = String(cbuf, n);
    BIO_free(bio);
    
    if(sbuf.equalsIgnoreCase("sha1WithRSAEncryption") ) {

        signatureAlgorithm = SHA1RSA;

    } else if(sbuf.equalsIgnoreCase("md5WithRSAEncryption") ) {

        signatureAlgorithm = MD5RSA;
    
    } else if(sbuf.equalsIgnoreCase("dsaWithSHA1") ) {

        signatureAlgorithm = SHA1DSA;

    } else {

        EVP_PKEY_free(pkey);

        LOGIT_ERROR("Unsupported signature algorithm: '" << sbuf << "'");
        BLOCXX_THROW(limal::RuntimeException, 
                     Format("Unsupported signature algorithm: '%1'", sbuf).c_str());

    }

    // get signature

    signature = ByteBuffer((char*)x509->signature->data, x509->signature->length);


    // get extensions

    extensions = X509v3CertificateExtensions_Priv(x509->cert_info->extensions);


    EVP_PKEY_free(pkey);
}

}
}
