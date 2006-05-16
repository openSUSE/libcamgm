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

  File:       CRLDataImpl.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_CRL_DATA_IMPL_HPP
#define    LIMAL_CA_MGM_CRL_DATA_IMPL_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <blocxx/COWIntrusiveCountableBase.hpp>

#include  "X509v3CRLExtensions_Priv.hpp"

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

	class RevocationEntryImpl : public blocxx::COWIntrusiveCountableBase
	{
	public:
		RevocationEntryImpl()
			: serial(0)
			, revocationDate(0)
			, revocationReason(CRLReason())
		{}

		RevocationEntryImpl(const RevocationEntryImpl& impl)
			: COWIntrusiveCountableBase(impl)
			, serial(impl.serial)
			, revocationDate(impl.revocationDate)
			, revocationReason(impl.revocationReason)
		{}

		~RevocationEntryImpl() {}

		RevocationEntryImpl* clone() const
		{
			return new RevocationEntryImpl(*this);
		}

		String      serial;
		time_t      revocationDate;
		CRLReason   revocationReason;

	};

	class CRLDataImpl : public blocxx::COWIntrusiveCountableBase
	{
	public:
		CRLDataImpl()
			: version(0)
			, fingerprint("")
			, lastUpdate(0)
			, nextUpdate(0)
			, issuer(DNObject())
			, signatureAlgorithm(E_SHA1RSA)
			, signature(ByteBuffer())
			, extensions(X509v3CRLExts_Priv())
			, revocationData(blocxx::Map<String, RevocationEntry>())
			, x509(NULL)
		{}

		CRLDataImpl(const CRLDataImpl& impl)
			: COWIntrusiveCountableBase(impl)
			, version(impl.version)
			, fingerprint(impl.fingerprint)
			, lastUpdate(impl.lastUpdate)
			, nextUpdate(impl.nextUpdate)
			, issuer(impl.issuer)
			, signatureAlgorithm(impl.signatureAlgorithm)
			, signature(impl.signature)
			, extensions(impl.extensions)
			, revocationData(impl.revocationData)
			, x509(X509_CRL_dup(impl.x509))
		{}

		~CRLDataImpl() {}

		CRLDataImpl* clone() const
		{
			return new CRLDataImpl(*this);
		}

		blocxx::Int32                        version;
		String                               fingerprint;
		time_t                               lastUpdate;
		time_t                               nextUpdate;
	
		DNObject                             issuer;
	
		SigAlg                               signatureAlgorithm;
		ByteBuffer                           signature;    
	
		X509v3CRLExts                        extensions;
	
		blocxx::Map<String, RevocationEntry> revocationData;

		X509_CRL                             *x509;
	};
}
}

#endif // LIMAL_CA_MGM_CRL_DATA_IMPL_HPP
