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


#include  <limal/Exception.hpp>
#include  <limal/PathUtils.hpp>
#include  <limal/PathInfo.hpp>

#include  "RequestDataImpl.hpp"
#include  "DNObject_Priv.hpp"
#include  "X509v3RequestExtensions_Priv.hpp"
#include  "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;
using namespace blocxx;

RequestData_Priv::RequestData_Priv()
	: RequestData()
{}

RequestData_Priv::RequestData_Priv(const ByteBuffer& request,
                                   FormatType formatType)
	: RequestData()
{
	init(request, formatType);
}

RequestData_Priv::RequestData_Priv(const std::string& requestPath,
                                   FormatType formatType)
	: RequestData()
{

	ByteBuffer ba = LocalManagement::readFile(requestPath);

	init(ba, formatType);
}

RequestData_Priv::RequestData_Priv(const RequestData_Priv& data)
	: RequestData(data)
{}

RequestData_Priv::~RequestData_Priv()
{}


void
RequestData_Priv::setVersion(uint32_t v)
{
	m_impl->version = v;
}

void
RequestData_Priv::setKeysize(uint32_t size)
{
	m_impl->keysize = size;
}

void
RequestData_Priv::setSubjectDN(const DNObject dn)
{
	std::vector<std::string> r = dn.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		CA_MGM_THROW(ca_mgm::ValueException, r[0].c_str());
	}
	m_impl->subject = dn;
}

void
RequestData_Priv::setKeyAlgorithm(KeyAlg alg)
{
	m_impl->pubkeyAlgorithm = alg;
}

void
RequestData_Priv::setPublicKey(const ByteBuffer key)
{
	m_impl->publicKey = key;
}

void
RequestData_Priv::setSignatureAlgorithm(SigAlg alg)
{
	m_impl->signatureAlgorithm = alg;
}

void
RequestData_Priv::setSignature(const ByteBuffer &sig)
{
	m_impl->signature = sig;
}

void
RequestData_Priv::setExtensions(const X509v3RequestExts &ext)
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
RequestData_Priv::setChallengePassword(const std::string &passwd)
{
	m_impl->challengePassword = passwd;
}

void
RequestData_Priv::setUnstructuredName(const std::string &name)
{
	m_impl->unstructuredName = name;
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
	m_impl->version = X509_REQ_get_version(x509) + 1;

    // get subject
	m_impl->subject = DNObject_Priv(x509->req_info->subject);

	EVP_PKEY *pkey = X509_REQ_get_pubkey(x509);

	if(pkey == NULL)
	{
		LOGIT_ERROR("Unable to get public key");
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("Unable to get the public key."));
	}

	if(pkey->type == EVP_PKEY_RSA)
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

		m_impl->publicKey = ByteBuffer((char*)y, len);

		free(y);
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

	// get keysize
	if (pkey->type == EVP_PKEY_RSA)
	{
		m_impl->keysize = BN_num_bits(pkey->pkey.rsa->n);
	}

	// get pubkeyAlgorithm
	if(pkey->type == EVP_PKEY_RSA ||
	   pkey->type == EVP_PKEY_RSA2 )
	{
		m_impl->pubkeyAlgorithm = E_RSA;
	}
	else if(pkey->type == EVP_PKEY_DSA  ||
	        pkey->type == EVP_PKEY_DSA1 ||
	        pkey->type == EVP_PKEY_DSA2 ||
	        pkey->type == EVP_PKEY_DSA3 ||
	        pkey->type == EVP_PKEY_DSA4  )
	{
		m_impl->pubkeyAlgorithm = E_DSA;
	}
	else if(pkey->type == EVP_PKEY_DH )
	{
		m_impl->pubkeyAlgorithm = E_DH;
	}
	else
	{
		EVP_PKEY_free(pkey);

		LOGIT_ERROR("Unsupported public key algorithm");
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("Unsupported public key algorithm."));
	}

	// get signatureAlgorithm
	char      *cbuf = NULL;
	BIO       *bio  = BIO_new(BIO_s_mem());
	i2a_ASN1_OBJECT(bio, x509->sig_alg->algorithm);
	int n = BIO_get_mem_data(bio, &cbuf);

	std::string sbuf = std::string(cbuf, n);
	BIO_free(bio);

	if(0 == str::compareCI(sbuf, "sha1WithRSAEncryption") )
	{
		m_impl->signatureAlgorithm = E_SHA1RSA;
	}
	else if(0 == str::compareCI(sbuf, "md5WithRSAEncryption") )
	{
		m_impl->signatureAlgorithm = E_MD5RSA;
	}
	else if(0 == str::compareCI(sbuf, "dsaWithSHA1") )
	{
		m_impl->signatureAlgorithm = E_SHA1DSA;
	}
	else
	{
		EVP_PKEY_free(pkey);

		LOGIT_ERROR("Unsupported signature algorithm: '" << sbuf << "'");
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             str::form(__("Unsupported signature algorithm %s."), sbuf.c_str()).c_str());
	}

	// get signature

	m_impl->signature = ByteBuffer((char*)x509->signature->data, x509->signature->length);

	// get attributes

	for (int i=0; i<sk_X509_ATTRIBUTE_num(x509->req_info->attributes); i++)
	{
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
		   nid != NID_pkcs9_unstructuredName     )
		{
			LOGIT_INFO("Unsupported attribute found: " << obj_tmp);
			continue;
		}

		if (a->single)
		{
			t=a->value.single;
			type=t->type;
			bs=t->value.bit_string;
		}
		else
		{
			ii=0;
			count=sk_ASN1_TYPE_num(a->value.set);

		get_next:

			at=sk_ASN1_TYPE_value(a->value.set,ii);
			type=at->type;
			bs=at->value.asn1_string;
		}

		if ( (type == V_ASN1_PRINTABLESTRING) ||
		     (type == V_ASN1_T61STRING) ||
		     (type == V_ASN1_IA5STRING))
		{
			char *d = new char[bs->length+1];
			memcpy(d, bs->data, bs->length);
			d[bs->length] = '\0';

			std::string s(d, bs->length);
			delete [] d;

			if(nid == NID_pkcs9_challengePassword)
			{
				m_impl->challengePassword += s;
			}
			else if (nid == NID_pkcs9_unstructuredName)
			{
				m_impl->unstructuredName += s;
			}
		}

		if (++ii < count) goto get_next;
	}

	// get extensions

	m_impl->extensions = X509v3RequestExts_Priv(X509_REQ_get_extensions(x509));
}

void
RequestData_Priv::init(const ByteBuffer& request,
                       FormatType formatType)
{
	BIO *bio;
	unsigned char *d = (unsigned char*)request.data();

	if( formatType == E_PEM )
	{
		bio = BIO_new_mem_buf(d, request.size());

		if(!bio)
		{
			LOGIT_ERROR("Can not create a memory BIO");
			CA_MGM_THROW(ca_mgm::MemoryException,
			             __("Cannot create a memory BIO."));
		}

		// create the X509 structure
		m_impl->x509 = PEM_read_bio_X509_REQ(bio, NULL, 0, NULL);
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

		m_impl->x509 = d2i_X509_REQ(NULL, &d2, request.size());

		d2 = NULL;
	}

	if(m_impl->x509 == NULL)
	{
		LOGIT_ERROR("Can not parse request");
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("Cannot parse the request."));
	}

	try
	{
		parseRequest(m_impl->x509);
	}
	catch(Exception &e)
	{
		X509_REQ_free(m_impl->x509);
		m_impl->x509 = NULL;

		CA_MGM_THROW_SUBEX(ca_mgm::SyntaxException,
		                   __("Error while parsing the request."),
		                   e);
	}
}

}
