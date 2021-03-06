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

#include <ca-mgm/LocalManagement.hpp>

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

#include  <ca-mgm/Date.hpp>
#include  <ca-mgm/String.hpp>

#include  <ca-mgm/Exception.hpp>
#include  <ca-mgm/PathInfo.hpp>

#include  "CertificateDataImpl.hpp"
#include  "Utils.hpp"
#include  "DNObject_Priv.hpp"
#include  "X509v3CertificateExtensions_Priv.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;

CertificateData_Priv::CertificateData_Priv()
	: CertificateData()
{}

CertificateData_Priv::CertificateData_Priv(const ByteBuffer &certificate,
                                           FormatType formatType)
	: CertificateData()
{
	init(certificate, formatType);
}

CertificateData_Priv::CertificateData_Priv(const std::string &certificatePath,
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
CertificateData_Priv::setVersion(uint32_t v)
{
	m_impl->version = v;
}

void
CertificateData_Priv::setSerial(const std::string& serial)
{
	if(!initHexCheck().isValid(serial))
	{
		LOGIT_ERROR("invalid serial: " << serial);
		CA_MGM_THROW(ca_mgm::ValueException,
		             // %1 is an invalid serial number
		             str::form(__("Invalid serial %s."), serial.c_str()).c_str());
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
	std::vector<std::string> r = issuer.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		CA_MGM_THROW(ca_mgm::ValueException, r[0].c_str());
	}
	m_impl->issuer = issuer;
}

void
CertificateData_Priv::setSubjectDN(const DNObject& subject)
{
	std::vector<std::string> r = subject.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		CA_MGM_THROW(ca_mgm::ValueException, r[0].c_str());
	}
	m_impl->subject = subject;
}

void
CertificateData_Priv::setKeysize(uint32_t size)
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
	std::vector<std::string> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		CA_MGM_THROW(ca_mgm::ValueException, r[0].c_str());
	}
	m_impl->extensions = ext;
}

void
CertificateData_Priv::setFingerprint(const std::string& fp)
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
			CA_MGM_THROW(ca_mgm::MemoryException,
			             __("Cannot create a memory BIO."));
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
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("Cannot parse the certificate."));
	}

	try
	{
		parseCertificate(m_impl->x509);
	}
	catch(Exception &e)
	{
		X509_free(m_impl->x509);
		m_impl->x509 = NULL;

		CA_MGM_THROW_SUBEX(ca_mgm::SyntaxException,
		                   __("Error while parsing the certificate."),
		                   e);
	}
}

void
CertificateData_Priv::parseCertificate(X509 *x509)
{
	unsigned char *ustringval = NULL;
	unsigned int n = 0;

	// get version
	setVersion(X509_get_version(x509) + 1);

	// get serial
	//
	// convert to hexadecimal version of the serial number

	BIO *bioS           = BIO_new(BIO_s_mem());
	ASN1_INTEGER *bs=X509_get_serialNumber(x509);
	std::string serialStr;
	for (int i=0; i<bs->length; i++)
	{
		if (BIO_printf(bioS,"%02x",bs->data[i]) <= 0)
		{
			LOGIT_ERROR("Can not parse serial.");
			CA_MGM_THROW(ca_mgm::RuntimeException,
						 __("Cannot parse serial."));
		}
	}
	n = BIO_get_mem_data(bioS, &ustringval);
	setSerial( str::toUpper(std::string(reinterpret_cast<const char*>(ustringval), n)));
	BIO_free(bioS);

	// get notBefore
	ASN1_TIME *t   = X509_get_notBefore(x509);
	char      *cbuf = new char[t->length + 1];

	memcpy(cbuf, t->data, t->length);
	cbuf[t->length] = '\0';

	std::string sbuf = std::string(cbuf);
	delete [] cbuf;
    Date notBefore(sbuf, "%y%m%d%H%M%S", true);

    // get notAfter
	t    = X509_get_notAfter(x509);
	cbuf = new char[t->length + 1];

	memcpy(cbuf, t->data, t->length);
	cbuf[t->length] = '\0';

	sbuf = std::string(cbuf);
	delete [] cbuf;
    Date notAfter(sbuf, "%y%m%d%H%M%S", true);

    setCertifyPeriode(notBefore, notAfter);

	// fingerprint

	ustringval = NULL;
	unsigned char md[EVP_MAX_MD_SIZE];
	n = 0;

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
	setFingerprint( std::string(reinterpret_cast<const char*>(ustringval), n));
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
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("Unable to get the public key."));
	}

	int pkey_type;
	#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
	pkey_type = EVP_PKEY_base_id(pkey);
	#else
	pkey_type = pkey->type;
	#endif

	if(pkey_type == EVP_PKEY_RSA)
	{
		rsa_st *rsa = EVP_PKEY_get1_RSA(pkey);

		if(!rsa)
		{
			LOGIT_ERROR("could not get RSA key");
			CA_MGM_THROW(ca_mgm::RuntimeException,
			             __("Could not get RSA key."));
		}

		unsigned char *y = NULL;

		int len  = i2d_RSA_PUBKEY(rsa, &y);

		setPublicKey( ByteBuffer((char*)y, len));
		// get keysize
		#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
		setKeysize( RSA_bits(rsa));
		#else
		setKeysize( BN_num_bits(rsa->n));
		#endif

		free(y); // ??
		RSA_free(rsa);
	}
	else
	{
		// unsupported type

		EVP_PKEY_free(pkey);

		LOGIT_ERROR("Unsupported public key type");
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("Unsupported public key type."));
	}

    // get pubkeyAlgorithm

	if(pkey_type == EVP_PKEY_RSA ||
	   pkey_type == EVP_PKEY_RSA2 )
	{
		setPublicKeyAlgorithm( E_RSA );
	}
	else if(pkey_type == EVP_PKEY_DSA  ||
	        pkey_type == EVP_PKEY_DSA1 ||
	        pkey_type == EVP_PKEY_DSA2 ||
	        pkey_type == EVP_PKEY_DSA3 ||
	        pkey_type == EVP_PKEY_DSA4  )
	{
		setPublicKeyAlgorithm( E_DSA );
	}
	else if(pkey_type == EVP_PKEY_DH )
	{
		setPublicKeyAlgorithm( E_DH );
	}
	else
	{
		EVP_PKEY_free(pkey);

		LOGIT_ERROR("Unsupported public key algorithm");
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("Unsupported public key algorithm."));
	}

	// get signatureAlgorithm

	n = 0;
	BIO *bio = BIO_new(BIO_s_mem());
	#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
	const ASN1_BIT_STRING *psig = NULL;
	const X509_ALGOR *palg = NULL;
	X509_get0_signature(&psig, &palg, x509);
	i2a_ASN1_OBJECT(bio, palg->algorithm);
	#else
	i2a_ASN1_OBJECT(bio, x509->cert_info->signature->algorithm);
	#endif
	n = BIO_get_mem_data(bio, &cbuf);

	sbuf = std::string(cbuf, n);
	BIO_free(bio);

        if(str::compareCI(sbuf, "sha1WithRSAEncryption") == 0)
        {
            setSignatureAlgorithm( E_SHA1RSA );
        }
        else if(str::compareCI(sbuf, "md5WithRSAEncryption") == 0)
        {
            setSignatureAlgorithm( E_MD5RSA );
        }
        else if(str::compareCI(sbuf, "dsaWithSHA1") == 0)
        {
            setSignatureAlgorithm( E_SHA1DSA );
        }
        else if(str::compareCI(sbuf, "sha224WithRSAEncryption") == 0 )
        {
            setSignatureAlgorithm(E_SHA224RSA);
        }
        else if(str::compareCI(sbuf, "sha256WithRSAEncryption") == 0 )
        {
            setSignatureAlgorithm(E_SHA256RSA);
        }
        else if(str::compareCI(sbuf, "sha384WithRSAEncryption") == 0 )
        {
            setSignatureAlgorithm(E_SHA384RSA);
        }
        else if(str::compareCI(sbuf, "sha512WithRSAEncryption") == 0 )
        {
            setSignatureAlgorithm(E_SHA512RSA);
        }
        else
        {
            EVP_PKEY_free(pkey);

            LOGIT_ERROR("Unsupported signature algorithm: '" << sbuf << "'");
            CA_MGM_THROW(ca_mgm::RuntimeException,
                         // %s is the unsupported signature algorithm string
                         str::form(__("Unsupported signature algorithm %s."), sbuf.c_str()).c_str());
        }

	// get signature

	#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
	setSignature( ByteBuffer((char*)psig->data, psig->length));
	#else
	setSignature( ByteBuffer((char*)x509->signature->data, x509->signature->length));
	#endif



	// get extensions

	#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
	setExtensions( X509v3CertificateExts_Priv((STACK_OF(X509_EXTENSION *))X509_get0_extensions(x509)));
	#else
	setExtensions( X509v3CertificateExts_Priv(x509->cert_info->extensions));
	#endif

	EVP_PKEY_free(pkey);
}

}
