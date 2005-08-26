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

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include  <fstream>
#include  <iostream>

#include  <limal/PathInfo.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>
#include  <blocxx/DateTime.hpp>

#include  "Utils.hpp"
#include  "DNObject_Priv.hpp"
#include  "X509v3CRLExtensions_Priv.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

RevocationEntry_Priv::RevocationEntry_Priv()
    : RevocationEntry()
{}

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

CRLData_Priv::CRLData_Priv(const String &crlPath)
    : CRLData()
{
    String sbuf;             // String buffer
    path::PathInfo crlFile(crlPath);

    if(!crlFile.exists()) {

        LOGIT_ERROR("CRL does not exist.");
        BLOCXX_THROW(limal::SystemException, "CRL does not exist.");

    }

    std::ifstream in(crlFile.toString().c_str());

    if (!in) {

        LOGIT_ERROR("Cannot open file: " << crlFile.toString() );
        BLOCXX_THROW(limal::SystemException,
                     Format("Cannot open file: %1", crlFile.toString()).c_str());

    }

    // read the certificate in PEM format into a StringStream buffer
    OStringStream _buf;
    _buf << in.rdbuf();

    in.close();

    char *d = new char[_buf.length()+1];
    memcpy(d, _buf.c_str(), _buf.length());

    // load the crl into a memory bio
    BIO *bio = BIO_new_mem_buf(d, _buf.length());

    if(!bio) {

        delete(d);

        LOGIT_ERROR("Can not create a memory BIO");
        BLOCXX_THROW(limal::MemoryException, "Can not create a memory BIO");

    }

    // create the X509 structure
    X509_CRL *x509 = PEM_read_bio_X509_CRL(bio, NULL, 0, NULL);
    BIO_free(bio);
    delete(d);

    if(x509 == NULL) {

        LOGIT_ERROR("Can not parse CRL");
        BLOCXX_THROW(limal::RuntimeException, "Can not parse CRL");

    }

    // get version
    version = X509_CRL_get_version(x509) + 1;

    // get lastUpdate
    ASN1_TIME *t   = X509_CRL_get_lastUpdate(x509);
    char      *cbuf = new char[t->length + 1];

    memcpy(cbuf, t->data, t->length);
    cbuf[t->length] = '\0';

    sbuf = String(cbuf);
    delete(cbuf);

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
    delete(cbuf);

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
    bio = BIO_new(BIO_s_mem());
    i2a_ASN1_OBJECT(bio, x509->sig_alg->algorithm);
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
        
        LOGIT_ERROR("Unsupported signature algorithm: '" << sbuf << "'");
        BLOCXX_THROW(limal::RuntimeException,
                     Format("Unsupported signature algorithm: '%1'", sbuf).c_str());

    }

    // get signature
    for(int k = 0; k < x509->signature->length; ++k) {

        signature.push_back(x509->signature->data[k]);

    }

    // get extensions
    extensions = X509v3CRLExtensions_Priv(x509->crl->extensions);
      
    // get revocationData

    X509_REVOKED *rev;
    
    for (int i=0; i<sk_X509_REVOKED_num(x509->crl->revoked); i++) {
        RevocationEntry_Priv revEntry;

        LOGIT_DEBUG("     >>>   START next run: " << i);
    
        rev=sk_X509_REVOKED_value(x509->crl->revoked,i);

        cbuf = new char[rev->revocationDate->length + 1];
        memcpy(cbuf, rev->revocationDate->data, rev->revocationDate->length);
        cbuf[rev->revocationDate->length] = '\0';
        
        sbuf = String(cbuf);
        LOGIT_DEBUG("Revocation Date: " << sbuf);

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

        revEntry.setRevocationDate(dt.get());
        delete(cbuf);

        Int64 serial =  ASN1_INTEGER_get(rev->serialNumber);

        String dummy;
        dummy.format("%02x", serial);

        LOGIT_DEBUG("Serial: " << dummy);
        revEntry.setSerial(dummy); 

        CRLReason crlreason;

        for(int x = 0; x < sk_X509_EXTENSION_num(rev->extensions); x++) {
            int nid = 0;
            String valueString;

            X509_EXTENSION *xe = sk_X509_EXTENSION_value(rev->extensions, x);

            char obj_tmp[80];
            i2t_ASN1_OBJECT(obj_tmp, 80, xe->object);
            nid = OBJ_txt2nid(obj_tmp);

            LOGIT_DEBUG("NID: " << obj_tmp << " " << nid);

            void *ext_str = NULL;
            X509V3_EXT_METHOD *method = X509V3_EXT_get(xe);
            unsigned char *p;

            p =  xe->value->data;
            if(method->it)
                ext_str = ASN1_item_d2i(NULL, &p, xe->value->length, ASN1_ITEM_ptr(method->it));
            else
                ext_str = method->d2i(NULL, &p, xe->value->length);

            if(method->i2s) {

                char *value = NULL;
                value = method->i2s(method, ext_str);
                valueString = String(value);
                if(value) OPENSSL_free(value);

            } else if(method->i2v) {
                LOGIT_INFO("Unsupported");
            } else if(method->i2r) {

                if(method->ext_nid == NID_hold_instruction_code) {
                    
                    char objtmp[80];
                    i2t_ASN1_OBJECT(objtmp, sizeof(objtmp), (ASN1_OBJECT*)ext_str);
                    
                    valueString = String(objtmp);

                } else if(method->ext_nid == NID_invalidity_date) {

                    char *value2 = NULL;
                    bio = BIO_new(BIO_s_mem());
                    if(!ASN1_GENERALIZEDTIME_print(bio, (ASN1_GENERALIZEDTIME*)ext_str)) {
                        LOGIT_ERROR("ERROR");
                    }
                    n = BIO_get_mem_data(bio, &value2);
                    valueString = String(value2, n);
                    LOGIT_DEBUG("NID_invalidity_date: " << valueString << " count: " << n);
                }
                
            } else {
                
                LOGIT_ERROR("Wrong method");
                continue;
            }

            LOGIT_DEBUG("Value: " << valueString);
        
            if(nid == NID_crl_reason) {
                
                if(valueString == "Unspecified") {
                    crlreason.setReason(CRLReason::unspecified);
                } else if(valueString == "Key Compromise") {
                    crlreason.setReason(CRLReason::keyCompromise);
                } else if(valueString == "CA Compromise") {
                    crlreason.setReason(CRLReason::CACompromise);
                } else if(valueString == "Affiliation Changed") {
                    crlreason.setReason(CRLReason::affiliationChanged);
                } else if(valueString == "Superseded") {
                    crlreason.setReason(CRLReason::superseded);
                } else if(valueString == "Cessation Of Operation") {
                    crlreason.setReason(CRLReason::cessationOfOperation);
                } else if(valueString == "Certificate Hold") {
                    crlreason.setReason(CRLReason::certificateHold);
                } else if(valueString == "Remove From CRL") {
                    crlreason.setReason(CRLReason::removeFromCRL);
                } else {
                    LOGIT_INFO("Unknown CRL reason:" << valueString);
                }
            } else if(nid == NID_hold_instruction_code) {

                // FIXME: Test with OID

                if(valueString == "Hold Instruction Call Issuer") {

                    crlreason.setHoldInstruction("holdInstructionCallIssuer");

                } else if(valueString == "Hold Instruction None") {

                    crlreason.setHoldInstruction("holdInstructionNone");

                } else if(valueString == "Hold Instruction Reject") {

                    crlreason.setHoldInstruction("holdInstructionReject");

                } else {
                    // OID ?? does this work ?
                    crlreason.setHoldInstruction(valueString);
                    
                }
            } else if(nid == NID_invalidity_date) {

                // e.g. Aug 18 15:56:46 2005 GMT
                /*
                  PerlRegEx dateRegEx("^(\\w)+\\s(\\d)+\\s(\\d)+:(\\d)+:(\\d)+\\s(\\d)+\\s(\\w)+$");
                
                  sa = dateRegEx.capture(valueString);
                  if(sa.size() != 8) {
                  // FIXME: something to free here?
                  
                  LOGIT_ERROR("Unable to parse date string: " << valueString);
                  BLOCXX_THROW(limal::SyntaxException,
                  Format("Unable to parse date string: %1", valueString).c_str());
                  }
                  String newtime = sa[6]+" "+sa[1]+" "+sa[2]+" "+sa[3]+":"+sa[4]+":"+sa[5]+sa[7];
                */
                DateTime dtime(valueString);
                
                if(crlreason.getReason() == CRLReason::keyCompromise) {
                    
                    crlreason.setKeyCompromiseDate(dtime.get());

                } else if(crlreason.getReason() == CRLReason::CACompromise) {

                    crlreason.setCACompromiseDate(dtime.get());

                } else {
                    LOGIT_INFO("Date with wrong reason");
                }

            } else {
                LOGIT_INFO("Unsupported NID: " << nid);
            }

            /*
              if(method->it) ASN1_item_free((ASN1_VALUE*)ext_str, ASN1_ITEM_ptr(method->it));
              else method->ext_free(ext_str);
            */
            //X509_EXTENSION_free(xe);

        }
        revEntry.setReason(crlreason);
        String ser = revEntry.getSerial();
        revocationData[ser] = revEntry;

        LOGIT_DEBUG("     >>>   ok, try next run: " << i);
    }

    LOGIT_DEBUG("     >>>   finish! ");
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
CRLData_Priv::setSignature(const ByteArray& sig)
{
    signature = sig;
}

void
CRLData_Priv::setExtensions(const X509v3CRLExtensions& ext)
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
