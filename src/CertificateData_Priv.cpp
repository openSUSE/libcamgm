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

#include  "CertificateDataImpl.hpp"
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
{}

CertificateData_Priv::CertificateData_Priv(const ByteBuffer &certificate,
                                           FormatType formatType)
	: CertificateData()
{
	init(certificate, formatType);
}

CertificateData_Priv::CertificateData_Priv(const String &certificatePath,
                                           FormatType formatType)
	: CertificateData()
{
	ByteBuffer ba = LocalManagement::readFile(certificatePath);

	init(ba, formatType);
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
	m_impl->version = v;
}

void
CertificateData_Priv::setSerial(const String& serial)
{
	if(!initHexCheck().isValid(serial))
	{
		LOGIT_ERROR("invalid serial: " << serial);
		BLOCXX_THROW(limal::ValueException, Format("invalid serial: %1", serial).c_str());
	}
	m_impl->serial = serial;
}

void
CertificateData_Priv::setCertifyPeriode(time_t start, time_t end)
{
	m_impl->notBefore = start;
	m_impl->notAfter  = end;
}

void
CertificateData_Priv::setIssuerDN(const DNObject& issuer)
{
	StringArray r = issuer.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(limal::ValueException, r[0].c_str());
	}
	m_impl->issuer = issuer;
}

void
CertificateData_Priv::setSubjectDN(const DNObject& subject)
{
	StringArray r = subject.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(limal::ValueException, r[0].c_str());
	}
	m_impl->subject = subject;
}

void
CertificateData_Priv::setKeysize(blocxx::UInt32 size)
{
	m_impl->keysize = size;
}

void
CertificateData_Priv::setPublicKeyAlgorithm(KeyAlg pubKeyAlg)
{
	m_impl->pubkeyAlgorithm = pubKeyAlg;
}

void
CertificateData_Priv::setPublicKey(const ByteBuffer derPublicKey)
{
	m_impl->publicKey = derPublicKey;
}

void
CertificateData_Priv::setSignatureAlgorithm(SigAlg sigAlg)
{
	m_impl->signatureAlgorithm = sigAlg;
}

void
CertificateData_Priv::setSignature(const ByteBuffer& sig)
{
	m_impl->signature = sig;
}

void
CertificateData_Priv::setExtensions(const X509v3CertificateExts& ext)
{
	StringArray r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(limal::ValueException, r[0].c_str());
	}
	m_impl->extensions = ext;
}

void
CertificateData_Priv::setFingerprint(const String& fp)
{
	m_impl->fingerprint = fp;
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
CertificateData_Priv::init(const ByteBuffer &certificate, FormatType formatType)
{
	BIO           *bio;
	unsigned char *d = (unsigned char*)certificate.data();

	if( formatType == E_PEM )
	{
		// load the certificate into a memory bio 
		bio = BIO_new_mem_buf(d, certificate.size());

		if(!bio)
		{            
			LOGIT_ERROR("Can not create a memory BIO");
			BLOCXX_THROW(limal::MemoryException, "Can not create a memory BIO");
		}

		// create the X509 structure
		m_impl->x509 = PEM_read_bio_X509(bio, NULL, 0, NULL);
		BIO_free(bio);

	}
	else
	{
		// => DER
#if OPENSSL_VERSION_NUMBER >= 0x0090801fL        
		const unsigned char *d2 = NULL;
		d2 = (const unsigned char*)d;
#else
		unsigned char *d2 = NULL;
		d2 = d;
#endif
        
		m_impl->x509 = d2i_X509(NULL, &d2, certificate.size());

		d2 = NULL;

	}

	if(m_impl->x509 == NULL)
	{
		LOGIT_ERROR("Can not parse certificate");
		BLOCXX_THROW(limal::RuntimeException, "Can not parse certificate");
	}

	try
	{
		parseCertificate(m_impl->x509);
	}
	catch(Exception &e)
	{
		X509_free(m_impl->x509);
		m_impl->x509 = NULL;

		BLOCXX_THROW_SUBEX(limal::SyntaxException,
		                   "Error at parsing the certificate",
		                   e);
	}
}

void
CertificateData_Priv::parseCertificate(X509 *x509) 
{
	// get version
	setVersion(X509_get_version(x509) + 1);
	
	// get serial
	//
	// convert to hexadecimal version of the serial number
	String serial;
	serial.format("%02llx",
	              String(i2s_ASN1_INTEGER(NULL,X509_get_serialNumber(x509))).toUInt64());
	setSerial(serial);

	// get notBefore
	ASN1_TIME *t   = X509_get_notBefore(x509);
	char      *cbuf = new char[t->length + 1];

	memcpy(cbuf, t->data, t->length);
	cbuf[t->length] = '\0';

	String sbuf = String(cbuf);
	delete [] cbuf;

	PerlRegEx r("^(\\d\\d)(\\d\\d)(\\d\\d)(\\d\\d)(\\d\\d)(\\d\\d)Z$");
	StringArray sa = r.capture(sbuf);
    
	if(sa.size() != 7)
	{
		LOGIT_ERROR("Can not parse date: " << sbuf);
		BLOCXX_THROW(limal::RuntimeException, 
		             Format("Can not parse date: %1", sbuf).c_str());
	}
	int year = 1970;
	if(sa[1].toInt() >= 70 && sa[1].toInt() <= 99)
	{
		year = sa[1].toInt() + 1900;
	}
	else
	{
		year = sa[1].toInt() + 2000;
	}

	DateTime dt(year, sa[2].toInt(), sa[3].toInt(),
	            sa[4].toInt(), sa[5].toInt(), sa[6].toInt(),
	            0, DateTime::E_UTC_TIME);
    
	time_t notBefore = dt.get();

    // get notAfter
	t    = X509_get_notAfter(x509);
	cbuf = new char[t->length + 1];

	memcpy(cbuf, t->data, t->length);
	cbuf[t->length] = '\0';

	sbuf = String(cbuf);
	delete [] cbuf;

	sa = r.capture(sbuf);
    
	if(sa.size() != 7)
	{
		LOGIT_ERROR("Can not parse date: " << sbuf);
		BLOCXX_THROW(limal::RuntimeException, 
		             Format("Can not parse date: %1", sbuf).c_str());
	}
	year = 1970;
	if(sa[1].toInt() >= 70 && sa[1].toInt() <= 99)
	{
		year = sa[1].toInt() + 1900;
	}
	else
	{
		year = sa[1].toInt() + 2000;
	}
    
	dt = DateTime(year, sa[2].toInt(), sa[3].toInt(),
	              sa[4].toInt(), sa[5].toInt(), sa[6].toInt(),
	              0, DateTime::E_UTC_TIME);
    
	setCertifyPeriode(notBefore, dt.get());
    
	// fingerprint
	
	unsigned char *ustringval = NULL;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int n = 0;
	
	BIO *bioFP           = BIO_new(BIO_s_mem());
	const EVP_MD *digest = EVP_sha1();
	
	if(X509_digest(x509, digest, md, &n))
	{
		BIO_printf(bioFP, "%s:", OBJ_nid2sn(EVP_MD_type(digest)));
		for (unsigned int j=0; j<n; j++)
		{
			BIO_printf (bioFP, "%02X",md[j]);
			if (j+1 != n) BIO_printf(bioFP,":");
		}
	}
	n = BIO_get_mem_data(bioFP, &ustringval);
	setFingerprint( String(reinterpret_cast<const char*>(ustringval), n));
	BIO_free(bioFP);
	
    // get issuer
    
	setIssuerDN( DNObject_Priv(X509_get_issuer_name(x509)));
    
	// get subject
    
	setSubjectDN( DNObject_Priv(X509_get_subject_name(x509)));
    
	// get public key
	EVP_PKEY *pkey = X509_get_pubkey(x509);
    
	if(pkey == NULL)
	{        
		LOGIT_ERROR("Unable to get public key");
		BLOCXX_THROW(limal::RuntimeException, "Unable to get public key");
	}
    
	if(pkey->type == EVP_PKEY_RSA)
	{
		rsa_st *rsa = EVP_PKEY_get1_RSA(pkey);
        
		if(!rsa)
		{
			LOGIT_ERROR("could not get RSA key");
			BLOCXX_THROW(limal::RuntimeException, "could not get RSA key");
		}
        
		unsigned char *y = NULL;
        
		int len  = i2d_RSA_PUBKEY(rsa, &y);

		setPublicKey( ByteBuffer((char*)y, len));
        
		free(y); // ??
		RSA_free(rsa);
	}
	else
	{
		// unsupported type
        
		EVP_PKEY_free(pkey);
        
		LOGIT_ERROR("Unsupported public key type");
		BLOCXX_THROW(limal::RuntimeException, "Unsupported public key type");
	}

	// get keysize
	if (pkey->type == EVP_PKEY_RSA)
	{
		setKeysize( BN_num_bits(pkey->pkey.rsa->n));
	}
	// no need for else; unsupported key type was fetched before


    // get pubkeyAlgorithm

	if(pkey->type == EVP_PKEY_RSA || 
	   pkey->type == EVP_PKEY_RSA2 )
	{
		setPublicKeyAlgorithm( E_RSA );
	}
	else if(pkey->type == EVP_PKEY_DSA  || 
	        pkey->type == EVP_PKEY_DSA1 || 
	        pkey->type == EVP_PKEY_DSA2 ||
	        pkey->type == EVP_PKEY_DSA3 ||
	        pkey->type == EVP_PKEY_DSA4  )
	{
		setPublicKeyAlgorithm( E_DSA );
	}
	else if(pkey->type == EVP_PKEY_DH )
	{
		setPublicKeyAlgorithm( E_DH );
	}
	else
	{
		EVP_PKEY_free(pkey);

		LOGIT_ERROR("Unsupported public key algorithm");
		BLOCXX_THROW(limal::RuntimeException, "Unsupported public key algorithm");
	}

	// get signatureAlgorithm
	
	n = 0;
	BIO *bio = BIO_new(BIO_s_mem());
	i2a_ASN1_OBJECT(bio, x509->cert_info->signature->algorithm);
	n = BIO_get_mem_data(bio, &cbuf);

	sbuf = String(cbuf, n);
	BIO_free(bio);
    
	if(sbuf.equalsIgnoreCase("sha1WithRSAEncryption") )
	{
		setSignatureAlgorithm( E_SHA1RSA );
	}
	else if(sbuf.equalsIgnoreCase("md5WithRSAEncryption") )
	{
		setSignatureAlgorithm( E_MD5RSA );
	}
	else if(sbuf.equalsIgnoreCase("dsaWithSHA1") )
	{
		setSignatureAlgorithm( E_SHA1DSA );
	}
	else
	{
		EVP_PKEY_free(pkey);
    	
		LOGIT_ERROR("Unsupported signature algorithm: '" << sbuf << "'");
		BLOCXX_THROW(limal::RuntimeException, 
		             Format("Unsupported signature algorithm: '%1'", sbuf).c_str());
	}

	// get signature

	setSignature( ByteBuffer((char*)x509->signature->data, x509->signature->length));


	// get extensions

	setExtensions( X509v3CertificateExts_Priv(x509->cert_info->extensions));
    
	EVP_PKEY_free(pkey);
}

}
}
