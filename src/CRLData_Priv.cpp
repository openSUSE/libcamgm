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

#include  <limal/Date.hpp>
#include  <limal/String.hpp>

#include  "CRLDataImpl.hpp"
#include  "Utils.hpp"
#include  "DNObject_Priv.hpp"
#include  "X509v3CRLExtensions_Priv.hpp"
#include  "CRLReason_Priv.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;
using namespace blocxx;

RevocationEntry_Priv::RevocationEntry_Priv()
	: RevocationEntry()
{}

RevocationEntry_Priv::RevocationEntry_Priv(X509_REVOKED *rev)
	: RevocationEntry()
{
	// get serial number
	unsigned char *ustringval = NULL;
	unsigned int n = 0;

	BIO *bioS           = BIO_new(BIO_s_mem());
	i2a_ASN1_INTEGER(bioS, rev->serialNumber);
	n = BIO_get_mem_data(bioS, &ustringval);

	setSerial(std::string(reinterpret_cast<const char*>(ustringval), n));
	BIO_free(bioS);

	LOGIT_DEBUG("=>=> New Entry with Serial: " << getSerial());

    // get revocationDate

	char *cbuf = new char[rev->revocationDate->length + 1];
	memcpy(cbuf, rev->revocationDate->data, rev->revocationDate->length);
	cbuf[rev->revocationDate->length] = '\0';

	std::string sbuf(cbuf);
	delete [] cbuf;
	LOGIT_DEBUG("Revocation Date: " << sbuf);
    Date dt(sbuf, "%y%m%d%H%M%S", true);

	setRevocationDate(dt);

    // get CRL Reason

	setReason( CRLReason_Priv(rev->extensions) );
}

RevocationEntry_Priv::RevocationEntry_Priv(const std::string&    serial,
                                           time_t           revokeDate,
                                           const CRLReason& reason)
	: RevocationEntry()
{
	if(!initHexCheck().isValid(serial))
	{
		LOGIT_ERROR("invalid serial: " << serial);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Invalid serial %s."), serial.c_str()).c_str());
	}
	std::vector<std::string> r = reason.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		CA_MGM_THROW(ca_mgm::ValueException, r[0].c_str());
	}
	setSerial( serial );
	setRevocationDate( revokeDate );
	setReason( reason );
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
RevocationEntry_Priv::setSerial(const std::string& serial)
{
	if(!initHexCheck().isValid(serial))
	{
		LOGIT_ERROR("invalid serial: " << serial);
		CA_MGM_THROW(ca_mgm::ValueException,
		             str::form(__("Invalid serial %s."), serial.c_str()).c_str());
	}
	m_impl->serial = serial;
}

void
RevocationEntry_Priv::setRevocationDate(time_t date)
{
	m_impl->revocationDate = date;
}

void
RevocationEntry_Priv::setReason(const CRLReason& reason)
{
	if(!reason.valid())
	{
		LOGIT_ERROR("invalid CRL reason");
		CA_MGM_THROW(ca_mgm::ValueException,
		             __("Invalid CRL reason."));
	}
	m_impl->revocationReason = reason;
}

// #############################################################################


CRLData_Priv::CRLData_Priv()
	: CRLData()
{}

CRLData_Priv::CRLData_Priv(const ByteBuffer &crl,
                           FormatType formatType)
	: CRLData()
{
	init(crl, formatType);
}


CRLData_Priv::CRLData_Priv(const std::string &crlPath,
                           FormatType formatType)
	: CRLData()
{
	ByteBuffer ba = LocalManagement::readFile(crlPath);

	init(ba, formatType);
}

CRLData_Priv::CRLData_Priv(const CRLData_Priv& data)
	: CRLData(data)
{}

CRLData_Priv::~CRLData_Priv()
{}

void
CRLData_Priv::setVersion(int32_t version)
{
	m_impl->version = version;
}

void
CRLData_Priv::setFingerprint(const std::string& fp)
{
	m_impl->fingerprint = fp;
}

void
CRLData_Priv::setValidityPeriod(time_t last,
                                time_t next)
{
	m_impl->lastUpdate = last;
	m_impl->nextUpdate = next;
}

void
CRLData_Priv::setIssuerDN(const DNObject& issuer)
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
CRLData_Priv::setSignatureAlgorithm(SigAlg sigAlg)
{
	m_impl->signatureAlgorithm = sigAlg;
}

void
CRLData_Priv::setSignature(const ByteBuffer& sig)
{
	m_impl->signature = sig;
}

void
CRLData_Priv::setExtensions(const X509v3CRLExts& ext)
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
CRLData_Priv::setRevocationData(const std::map<std::string, RevocationEntry>& data)
{
	std::vector<std::string> r = checkRevocationData(data);
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		CA_MGM_THROW(ca_mgm::ValueException, r[0].c_str());
	}
	m_impl->revocationData = data;
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
	setVersion( X509_CRL_get_version(x509) + 1 );

	// get fingerprint

	unsigned char *ustringval = NULL;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int n = 0;

	BIO *bioFP           = BIO_new(BIO_s_mem());
	const EVP_MD *digest = EVP_sha1();

	if(X509_CRL_digest(x509, digest, md, &n))
	{
		BIO_printf(bioFP, "%s:", OBJ_nid2sn(EVP_MD_type(digest)));
		for (unsigned int j=0; j<n; j++)
		{
			BIO_printf (bioFP, "%02X",md[j]);
			if (j+1 != n) BIO_printf(bioFP,":");
		}
	}
	n = BIO_get_mem_data(bioFP, &ustringval);
	setFingerprint(std::string(reinterpret_cast<const char*>(ustringval), n));
	BIO_free(bioFP);

    // get lastUpdate
	ASN1_TIME *t   = X509_CRL_get_lastUpdate(x509);
	char      *cbuf = new char[t->length + 1];

	memcpy(cbuf, t->data, t->length);
	cbuf[t->length] = '\0';

	std::string sbuf(cbuf);
	delete [] cbuf;
    Date dt(sbuf, "%y%m%d%H%M%S", true);
	time_t lastUpdate = dt;

    // get nextUpdate
	t    = X509_CRL_get_nextUpdate(x509);
	cbuf = new char[t->length + 1];

	memcpy(cbuf, t->data, t->length);
	cbuf[t->length] = '\0';

	sbuf = std::string(cbuf);
	delete [] cbuf;
    dt = Date(sbuf, "%y%m%d%H%M%S", true);

	time_t nextUpdate = dt;

	setValidityPeriod(lastUpdate, nextUpdate);

	// get issuer

	setIssuerDN( DNObject_Priv(x509->crl->issuer) );

	// get signatureAlgorithm
	n = 0;
	BIO *bio = BIO_new(BIO_s_mem());
	i2a_ASN1_OBJECT(bio, x509->sig_alg->algorithm);
	n = BIO_get_mem_data(bio, &cbuf);

	sbuf = std::string(cbuf, n);
	BIO_free(bio);

	if(str::compareCI(sbuf, "sha1WithRSAEncryption") == 0 )
	{
		setSignatureAlgorithm(E_SHA1RSA);
	}
	else if(str::compareCI(sbuf, "md5WithRSAEncryption") == 0)
	{
		setSignatureAlgorithm(E_MD5RSA);
	}
	else if(str::compareCI(sbuf, "dsaWithSHA1") == 0 )
	{
		setSignatureAlgorithm(E_SHA1DSA);
	}
	else
	{
		LOGIT_ERROR("Unsupported signature algorithm: '" << sbuf << "'");
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             str::form(__("Unsupported signature algorithm %s."), sbuf.c_str()).c_str());
	}

	// get signature

	setSignature( ByteBuffer((char*)x509->signature->data, x509->signature->length));

	// get extensions
	setExtensions( X509v3CRLExts_Priv(x509->crl->extensions));

	// get revocationData

	std::map<std::string, RevocationEntry> revData;

	for (int i=0; i<sk_X509_REVOKED_num(x509->crl->revoked); i++)
	{
		RevocationEntry_Priv revEntry(sk_X509_REVOKED_value(x509->crl->revoked,i));

		std::string ser = revEntry.getSerial();
		revData[ser] = revEntry;
	}
	setRevocationData(revData);
}

void
CRLData_Priv::init(const ByteBuffer &crl, FormatType formatType)
{
	BIO *bio;
	unsigned char *d = (unsigned char*)crl.data();

	if( formatType == E_PEM )
	{
		// load the crl into a memory bio
		bio = BIO_new_mem_buf(d, crl.size());

		if(!bio)
		{
			LOGIT_ERROR("Can not create a memory BIO");
			CA_MGM_THROW(ca_mgm::MemoryException,
			             __("Cannot create a memory BIO."));
		}

		// create the X509 structure
		m_impl->x509 = PEM_read_bio_X509_CRL(bio, NULL, 0, NULL);
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

		m_impl->x509 = d2i_X509_CRL(NULL, &d2, crl.size());

		d2 = NULL;
	}

	if(m_impl->x509 == NULL)
	{
		LOGIT_ERROR("Can not parse CRL");
		CA_MGM_THROW(ca_mgm::RuntimeException,
		             __("Cannot parse CRL."));
	}

	try
	{
		parseCRL(m_impl->x509);
	}
	catch(Exception &e)
	{
		X509_CRL_free(m_impl->x509);
		m_impl->x509 = NULL;

		CA_MGM_THROW_SUBEX(ca_mgm::SyntaxException,
		                   __("Error parsing the CRL."),
		                   e);
	}
}

}
