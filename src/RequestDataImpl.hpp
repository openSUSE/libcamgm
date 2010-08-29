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

  File:       RequestDataImpl.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    CA_MGM_REQUEST_DATA_IMPL_HPP
#define    CA_MGM_REQUEST_DATA_IMPL_HPP

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>


#include  "X509v3RequestExtensions_Priv.hpp"


namespace CA_MGM_NAMESPACE {

class RequestDataImpl
{
public:

	RequestDataImpl()
		: version(0)
		, subject(DNObject())
		, keysize(0)
		, pubkeyAlgorithm(E_RSA)
		, publicKey(ByteBuffer())
		, signatureAlgorithm(E_SHA1RSA)
		, signature(ByteBuffer())
		, extensions(X509v3RequestExts_Priv())
		, challengePassword("")
		, unstructuredName("")
		, x509(NULL)
	{}

	RequestDataImpl(const RequestDataImpl& impl)
		: version(impl.version)
		, subject(impl.subject)
		, keysize(impl.keysize)
		, pubkeyAlgorithm(impl.pubkeyAlgorithm)
		, publicKey(impl.publicKey)
		, signatureAlgorithm(impl.signatureAlgorithm)
		, signature(impl.signature)
		, extensions(impl.extensions)
		, challengePassword(impl.challengePassword)
		, unstructuredName(impl.unstructuredName)
		, x509(X509_REQ_dup(impl.x509))
	{}

	~RequestDataImpl()
	{
		if(x509 != NULL)
		{
			X509_REQ_free(x509);
			x509 = NULL;
		}
	}

	RequestDataImpl* clone() const
	{
		return new RequestDataImpl(*this);
	}

	uint32_t    version;

	DNObject          subject;
	uint32_t    keysize;

	KeyAlg            pubkeyAlgorithm;

		// DER des public key
		//   man EVP_PKEY_set1_RSA
		//   man EVP_PKEY_get1_RSA
		//   man i2d_RSAPublicKey     => i2d == internal to DER
		//   man d2i_RSAPublicKey     => d2i == DER to internal
	ByteBuffer        publicKey;

	SigAlg            signatureAlgorithm;
	ByteBuffer        signature;

	X509v3RequestExts extensions;

        // attributes
	std::string            challengePassword;
	std::string            unstructuredName;

	X509_REQ          *x509;
};
}

#endif // CA_MGM_REQUEST_DATA_IMPL_HPP
