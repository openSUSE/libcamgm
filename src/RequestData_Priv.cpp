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

  File:       RequestData_Priv.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  "RequestData_Priv.hpp"

#include <limal/ca-mgm/LocalManagement.hpp>

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

#include  <blocxx/DateTime.hpp>
#include  <blocxx/Format.hpp>
#include  <limal/Exception.hpp>
#include  <limal/PathUtils.hpp>
#include  <limal/PathInfo.hpp>

#include  "DNObject_Priv.hpp"
#include  "X509v3RequestExtensions_Priv.hpp"
#include  "Utils.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;

RequestData_Priv::RequestData_Priv()
    : RequestData()
{
}

RequestData_Priv::RequestData_Priv(const ByteBuffer& request, 
                                   FormatType formatType)
    : RequestData()
{
    BIO *bio;
    X509_REQ *x509 = NULL;

    unsigned char *d = (unsigned char*)request.data();

    if( formatType == E_PEM ) {

        bio = BIO_new_mem_buf(d, request.size());

        if(!bio) {
            
            LOGIT_ERROR("Can not create a memory BIO");
            BLOCXX_THROW(limal::MemoryException, "Can not create a memory BIO");
            
        }

        // create the X509 structure
        x509 = PEM_read_bio_X509_REQ(bio, NULL, 0, NULL);
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
        
        x509 = d2i_X509_REQ(NULL, &d2, request.size());

        d2 = NULL;
    }

    if(x509 == NULL) {

        LOGIT_ERROR("Can not parse request");
        BLOCXX_THROW(limal::RuntimeException, "Can not parse request");

    }

    try {

        parseRequest(x509);
        
    } catch(Exception &e) {
        
        X509_REQ_free(x509);

        BLOCXX_THROW_SUBEX(limal::SyntaxException,
                           "Error at parsing the request",
                           e);

    }

    X509_REQ_free(x509);
}

RequestData_Priv::RequestData_Priv(const String& requestPath, 
                                   FormatType formatType)
    : RequestData()
{

    ByteBuffer ba = LocalManagement::readFile(requestPath);

    // FIXME: I do not know if this is the right way :-)
    *this = RequestData_Priv(ba, formatType);

}

RequestData_Priv::RequestData_Priv(const RequestData_Priv& data)
    : RequestData(data)
{
}

RequestData_Priv::~RequestData_Priv()
{
}


void
RequestData_Priv::setVersion(blocxx::UInt32 v)
{
    version = v;
}

void
RequestData_Priv::setKeysize(blocxx::UInt32 size)
{
    keysize = size;
}

void
RequestData_Priv::setSubjectDN(const DNObject dn)
{
    StringArray r = dn.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    subject = dn;
}

void
RequestData_Priv::setKeyAlgorithm(KeyAlg alg)
{
    pubkeyAlgorithm = alg; 
}

void
RequestData_Priv::setPublicKey(const ByteBuffer key)
{
    publicKey = key;
}

void
RequestData_Priv::setSignatureAlgorithm(SigAlg alg)
{
    signatureAlgorithm = alg;
}

void
RequestData_Priv::setSignature(const ByteBuffer &sig)
{
    signature = sig;
}

void
RequestData_Priv::setExtensions(const X509v3RequestExts &ext)
{
    StringArray r = ext.verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    extensions = ext;
}

void
RequestData_Priv::setChallengePassword(const String &passwd)
{
    challengePassword = passwd;
}

void
RequestData_Priv::setUnstructuredName(const String &name)
{
    unstructuredName = name;
}


//    private:


RequestData_Priv&
RequestData_Priv::operator=(const RequestData_Priv& data)
{
    if(this == &data) return *this;
    
    RequestData::operator=(data);

    return *this;
}

void
RequestData_Priv::parseRequest(X509_REQ *x509)
{
    // get version
    version = X509_REQ_get_version(x509) + 1; // ??  + 1;

    // get subject
    subject = DNObject_Priv(x509->req_info->subject);

    EVP_PKEY *pkey = X509_REQ_get_pubkey(x509);

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

        free(y);
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

    // get pubkeyAlgorithm
    if(pkey->type == EVP_PKEY_RSA ||
       pkey->type == EVP_PKEY_RSA2 ) {
        
        pubkeyAlgorithm = E_RSA;
        
    } else if(pkey->type == EVP_PKEY_DSA  ||
              pkey->type == EVP_PKEY_DSA1 ||
              pkey->type == EVP_PKEY_DSA2 ||
              pkey->type == EVP_PKEY_DSA3 ||
              pkey->type == EVP_PKEY_DSA4  ) {
        
        pubkeyAlgorithm = E_DSA;
        
    } else if(pkey->type == EVP_PKEY_DH ) {
        
        pubkeyAlgorithm = E_DH;
        
    } else {
        
        EVP_PKEY_free(pkey);
        
        LOGIT_ERROR("Unsupported public key algorithm");
        BLOCXX_THROW(limal::RuntimeException, "Unsupported public key algorithm");
        
    }

    // get signatureAlgorithm
    char      *cbuf = NULL;
    BIO       *bio  = BIO_new(BIO_s_mem());
    i2a_ASN1_OBJECT(bio, x509->sig_alg->algorithm);
    int n = BIO_get_mem_data(bio, &cbuf);

    String sbuf = String(cbuf, n);
    BIO_free(bio);

    if(sbuf.equalsIgnoreCase("sha1WithRSAEncryption") ) {

        signatureAlgorithm = E_SHA1RSA;

    } else if(sbuf.equalsIgnoreCase("md5WithRSAEncryption") ) {

        signatureAlgorithm = E_MD5RSA;

    } else if(sbuf.equalsIgnoreCase("dsaWithSHA1") ) {

        signatureAlgorithm = E_SHA1DSA;

    } else {

        EVP_PKEY_free(pkey);

        LOGIT_ERROR("Unsupported signature algorithm: '" << sbuf << "'");
        BLOCXX_THROW(limal::RuntimeException,
                     Format("Unsupported signature algorithm: '%1'", sbuf).c_str());

    }

    // get signature

    signature = ByteBuffer((char*)x509->signature->data, x509->signature->length);

    // get attributes

    for (int i=0; i<sk_X509_ATTRIBUTE_num(x509->req_info->attributes); i++) {

        ASN1_TYPE *at;
        X509_ATTRIBUTE *a;
        ASN1_BIT_STRING *bs=NULL;
        ASN1_TYPE *t;
        int type=0,count=1,ii=0;

        a=sk_X509_ATTRIBUTE_value(x509->req_info->attributes,i);
        if(X509_REQ_extension_nid(OBJ_obj2nid(a->object)))
            continue;

        char obj_tmp[80];
        i2t_ASN1_OBJECT(obj_tmp, sizeof(obj_tmp), a->object);
        int nid = OBJ_txt2nid(obj_tmp);
        if(nid != NID_pkcs9_challengePassword && 
           nid != NID_pkcs9_unstructuredName     ) {

            LOGIT_INFO("Unsupported attribute found: " << obj_tmp);
            continue;
        }

        if (a->single) {
            
            t=a->value.single;
            type=t->type;
            bs=t->value.bit_string;

        } else {
            
            ii=0;
            count=sk_ASN1_TYPE_num(a->value.set);

        get_next:
            
            at=sk_ASN1_TYPE_value(a->value.set,ii);
            type=at->type;
            bs=at->value.asn1_string;
        }

        if ( (type == V_ASN1_PRINTABLESTRING) ||
             (type == V_ASN1_T61STRING) ||
             (type == V_ASN1_IA5STRING)) {
            
            char *d = new char[bs->length+1];
            memcpy(d, bs->data, bs->length);
            d[bs->length] = '\0';

            String s(d, bs->length);
            delete [] d;
            
            if(nid == NID_pkcs9_challengePassword) {
                
                challengePassword += s;
                
            } else if (nid == NID_pkcs9_unstructuredName) {
                
                unstructuredName += s;                
                
            }
        }

        if (++ii < count) goto get_next;
    }

    // get extensions

    extensions = X509v3RequestExts_Priv(X509_REQ_get_extensions(x509));

    // get human readable format

    unsigned char *ustringval = NULL;
    BIO *bio2 = BIO_new(BIO_s_mem());

	X509_REQ_print_ex(bio2, x509, 0, 0);
	n = BIO_get_mem_data(bio2, &ustringval);

	text = String((const char*)ustringval, n);
	BIO_free(bio2);

	ustringval = NULL;
	
	BIO *bio3 = BIO_new(BIO_s_mem());

	X509V3_extensions_print(bio3, NULL, X509_REQ_get_extensions(x509), 0, 4);
	n = BIO_get_mem_data(bio3, &ustringval);
	
	extText = String((const char*)ustringval, n);
	BIO_free(bio3);

}

}
}
