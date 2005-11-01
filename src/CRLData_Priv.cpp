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

  File:       CRLData_Priv.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  "CRLData_Priv.hpp"

#include  <limal/ca-mgm/LocalManagement.hpp>

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include  <limal/PathInfo.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>
#include  <blocxx/DateTime.hpp>

#include  "Utils.hpp"
#include  "DNObject_Priv.hpp"
#include  "X509v3CRLExtensions_Priv.hpp"
#include  "CRLReason_Priv.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;

RevocationEntry_Priv::RevocationEntry_Priv()
    : RevocationEntry()
{}

RevocationEntry_Priv::RevocationEntry_Priv(X509_REVOKED *rev)
    : RevocationEntry()
{
    // get serial number
    
    UInt64 serial =  ASN1_INTEGER_get(rev->serialNumber);
    
    String sbuf;
    sbuf.format("%02llx", serial);
    
    LOGIT_DEBUG("=>=> New Entry with Serial: " << sbuf);
    setSerial(sbuf); 
    
    // get revocationDate

    char *cbuf = new char[rev->revocationDate->length + 1];
    memcpy(cbuf, rev->revocationDate->data, rev->revocationDate->length);
    cbuf[rev->revocationDate->length] = '\0';
    
    sbuf = String(cbuf);
    delete [] cbuf;

    LOGIT_DEBUG("Revocation Date: " << sbuf);

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
    
    DateTime dt = DateTime(year, sa[2].toInt(), sa[3].toInt(),
                           sa[4].toInt(), sa[5].toInt(), sa[6].toInt(),
                           0, DateTime::E_UTC_TIME);
    
    setRevocationDate(dt.get());

    // get CRL Reason

    revocationReason = CRLReason_Priv(rev->extensions);
    
}

RevocationEntry_Priv::RevocationEntry_Priv(const String&    serial, 
                                           time_t           revokeDate,
                                           const CRLReason& reason)
    : RevocationEntry()
{
    if(!initHexCheck().isValid(serial)) {
        LOGIT_ERROR("invalid serial: " << serial);
        BLOCXX_THROW(limal::ValueException, Format("invalid serial: %1", serial).c_str());
    }
    StringArray r = reason.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    this->serial     = serial;
    revocationDate   = revokeDate;
    revocationReason = reason;
}

RevocationEntry_Priv::RevocationEntry_Priv(const RevocationEntry_Priv& entry)
    : RevocationEntry(entry)
{}

RevocationEntry_Priv::~RevocationEntry_Priv()
{}

RevocationEntry_Priv&
RevocationEntry_Priv::operator=(const RevocationEntry_Priv& entry)
{
    if(this == &entry) return *this;
    
    RevocationEntry::operator=(entry);
    
    return *this;
}

void
RevocationEntry_Priv::setSerial(const String& serial)
{
    if(!initHexCheck().isValid(serial)) {
        LOGIT_ERROR("invalid serial: " << serial);
        BLOCXX_THROW(limal::ValueException, Format("invalid serial: %1", serial).c_str());
    }
    this->serial = serial;
}

void
RevocationEntry_Priv::setRevocationDate(time_t date)
{
    revocationDate = date;
}

void
RevocationEntry_Priv::setReason(const CRLReason& reason)
{
    if(!reason.valid()) {
        LOGIT_ERROR("invalid CRL reason");
        BLOCXX_THROW(limal::ValueException, "invalid CRL reason");
    }
    revocationReason = reason;
}


// #############################################################################


CRLData_Priv::CRLData_Priv()
    : CRLData()
{}

CRLData_Priv::CRLData_Priv(const ByteBuffer &crl,
                           FormatType formatType)
    : CRLData()
{
    BIO *bio;
    X509_CRL *x509 = NULL;

    unsigned char *d = (unsigned char*)crl.data();

    if( formatType == E_PEM ) {

        // load the crl into a memory bio
        bio = BIO_new_mem_buf(d, crl.size());

        if(!bio) {
            
            LOGIT_ERROR("Can not create a memory BIO");
            BLOCXX_THROW(limal::MemoryException, "Can not create a memory BIO");
            
        }

        // create the X509 structure
        x509 = PEM_read_bio_X509_CRL(bio, NULL, 0, NULL);
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
        
        x509 = d2i_X509_CRL(NULL, &d2, crl.size());

        d2 = NULL;
    }

    if(x509 == NULL) {

        LOGIT_ERROR("Can not parse CRL");
        BLOCXX_THROW(limal::RuntimeException, "Can not parse CRL");

    }

    try {

        parseCRL(x509);

    } catch(Exception &e) {

        X509_CRL_free(x509);

        BLOCXX_THROW_SUBEX(limal::SyntaxException,
                           "Error at parsing the CRL",
                           e);
        
    }
    
    X509_CRL_free(x509);
}


CRLData_Priv::CRLData_Priv(const String &crlPath,
                           FormatType formatType)
    : CRLData()
{
    ByteBuffer ba = LocalManagement::readFile(crlPath);

    // FIXME: I do not know if this is the right way :-)
    *this = CRLData_Priv(ba, formatType);

}

CRLData_Priv::CRLData_Priv(const CRLData_Priv& data)
    : CRLData(data)
{
}

CRLData_Priv::~CRLData_Priv()
{}

void
CRLData_Priv::setVersion(blocxx::Int32 version)
{
    this->version = version;
}

void
CRLData_Priv::setValidityPeriod(time_t last,
                                time_t next)
{
    lastUpdate = last;
    nextUpdate = next;
}

void
CRLData_Priv::setIssuerDN(const DNObject& issuer)
{
    StringArray r = issuer.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    this->issuer = issuer;
}

void
CRLData_Priv::setSignatureAlgorithm(SigAlg sigAlg)
{
    signatureAlgorithm = sigAlg;
}

void
CRLData_Priv::setSignature(const ByteBuffer& sig)
{
    signature = sig;
}

void
CRLData_Priv::setExtensions(const X509v3CRLExts& ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    extensions = ext;
}

void
CRLData_Priv::setRevocationData(const blocxx::Map<String, RevocationEntry>& data)
{
    StringArray r = checkRevocationData(data);
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    revocationData = data;
}


//  private:


CRLData_Priv&
CRLData_Priv::operator=(const CRLData_Priv& data)
{
    if(this == &data) return *this;

    CRLData::operator=(data);

    return *this;
}

void
CRLData_Priv::parseCRL(X509_CRL *x509)
{
    
    // get version
    version = X509_CRL_get_version(x509) + 1;

    // get lastUpdate
    ASN1_TIME *t   = X509_CRL_get_lastUpdate(x509);
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
    lastUpdate = dt.get();

    // get nextUpdate
    t    = X509_CRL_get_nextUpdate(x509);
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
    nextUpdate = dt.get();

    // get issuer

    issuer = DNObject_Priv(x509->crl->issuer);

    // get signatureAlgorithm
    BIO *bio = BIO_new(BIO_s_mem());
    i2a_ASN1_OBJECT(bio, x509->sig_alg->algorithm);
    int n = BIO_get_mem_data(bio, &cbuf);

    sbuf = String(cbuf, n);
    BIO_free(bio);
    
    if(sbuf.equalsIgnoreCase("sha1WithRSAEncryption") ) {
        
        signatureAlgorithm = E_SHA1RSA;
        
    } else if(sbuf.equalsIgnoreCase("md5WithRSAEncryption") ) {
        
        signatureAlgorithm = E_MD5RSA;
        
    } else if(sbuf.equalsIgnoreCase("dsaWithSHA1") ) {
        
        signatureAlgorithm = E_SHA1DSA;
        
    } else {
        
        LOGIT_ERROR("Unsupported signature algorithm: '" << sbuf << "'");
        BLOCXX_THROW(limal::RuntimeException,
                     Format("Unsupported signature algorithm: '%1'", sbuf).c_str());

    }

    // get signature

    signature = ByteBuffer((char*)x509->signature->data, x509->signature->length);

    // get extensions
    extensions = X509v3CRLExts_Priv(x509->crl->extensions);
      
    // get revocationData

    for (int i=0; i<sk_X509_REVOKED_num(x509->crl->revoked); i++) {

        RevocationEntry_Priv revEntry(sk_X509_REVOKED_value(x509->crl->revoked,i));

        String ser = revEntry.getSerial();
        revocationData[ser] = revEntry;

    }
}

}
}
