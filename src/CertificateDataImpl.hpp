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

  File:       CertificateDataImpl.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_CERTIFICATE_DATA_IMPL_HPP
#define    LIMAL_CA_MGM_CERTIFICATE_DATA_IMPL_HPP

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>


#include  "X509v3CertificateExtensions_Priv.hpp"


namespace CA_MGM_NAMESPACE {

class CertificateDataImpl
{
public:
	CertificateDataImpl()
		: version(0)
		, serial("")
		, fingerprint("")
		, notBefore(0)
		, notAfter(0)
		, issuer(DNObject())
		, subject(DNObject())
		, keysize(2048)
		, pubkeyAlgorithm(E_RSA)
		, publicKey(ByteBuffer())
		, signatureAlgorithm(E_SHA1RSA)
		, signature(ByteBuffer())
		, extensions(X509v3CertificateExts_Priv())
		, x509(NULL)
	{}

	CertificateDataImpl(const CertificateDataImpl& impl)
		: version(impl.version)
		, serial(impl.serial)
		, fingerprint(impl.fingerprint)
		, notBefore(impl.notBefore)
		, notAfter(impl.notAfter)
		, issuer(impl.issuer)
		, subject(impl.subject)
		, keysize(impl.keysize)
		, pubkeyAlgorithm(impl.pubkeyAlgorithm)
		, publicKey(impl.publicKey)
		, signatureAlgorithm(impl.signatureAlgorithm)
		, signature(impl.signature)
		, extensions(impl.extensions)
		, x509(X509_dup(impl.x509))
	{}

	~CertificateDataImpl()
	{
		if(x509 != NULL)
		{
			X509_free(x509);
			x509 = NULL;
		}
	}

	CertificateDataImpl* clone() const
	{
		return new CertificateDataImpl(*this);
	}

	uint32_t              version;   // allowed 1, 2, 3
	std::string           serial;
	std::string           fingerprint;
	time_t                notBefore;
	time_t                notAfter;

	DNObject              issuer;
	DNObject              subject;
	uint32_t        keysize;

	KeyAlg                pubkeyAlgorithm;

	ByteBuffer            publicKey;

	SigAlg                signatureAlgorithm;
	ByteBuffer            signature;

	X509v3CertificateExts extensions;

	X509                  *x509;

};

}

#endif // LIMAL_CA_MGM_CERTIFICATE_DATA_IMPL_HPP
