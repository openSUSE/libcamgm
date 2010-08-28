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

  File:       CRLData.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_CRL_DATA_HPP
#define    LIMAL_CA_MGM_CRL_DATA_HPP

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>
#include  <ca-mgm/CRLReason.hpp>
#include  <ca-mgm/DNObject.hpp>
#include  <ca-mgm/X509v3CRLExtensions.hpp>
#include  <ca-mgm/ByteBuffer.hpp>
#include <ca-mgm/PtrTypes.hpp>

namespace CA_MGM_NAMESPACE {

	class RevocationEntryImpl;
	class CRLDataImpl;

	class RevocationEntry {
	public:
		RevocationEntry();
		RevocationEntry(const RevocationEntry& entry);
		virtual ~RevocationEntry();

#ifndef SWIG

		RevocationEntry&
		operator=(const RevocationEntry& entry);

#endif

		std::string
		getSerial() const;

		time_t
		getRevocationDate() const;

		CRLReason
		getReason() const;

		virtual bool
		valid() const;

		virtual std::vector<std::string>
		verify() const;

		virtual std::vector<std::string>
		dump() const;

	protected:
		ca_mgm::RWCOW_pointer<RevocationEntryImpl> m_impl;

	};

	/**
     * @brief Read-only data representation of a CRL
     *
     * This class is a read-only data representation of a CRL.
     */
	class CRLData {
	public:
		CRLData(const CRLData& data);
		virtual ~CRLData();

#ifndef SWIG

		CRLData&
		operator=(const CRLData& data);

#endif

		int32_t
		getVersion() const;

		std::string
		getFingerprint() const;

		time_t
		getLastUpdateDate() const;

		time_t
		getNextUpdateDate() const;

		DNObject
		getIssuerDN() const;

		SigAlg
		getSignatureAlgorithm() const;

		std::string
		getSignatureAlgorithmAsString() const;

		ca_mgm::ByteBuffer
		getSignature() const;

		X509v3CRLExts
		getExtensions() const;

		std::map<std::string, RevocationEntry>
		getRevocationData() const;

		RevocationEntry
		getRevocationEntry(const std::string& oid);

		/**
		 * Return the CRL data as human readable text.
		 * (Format may change)
		 */
		std::string
		getCRLAsText() const;

		/**
		 * Return the CRL extensions as human readable text.
		 * (Format may change)
		 */
		std::string
		getExtensionsAsText() const;

		virtual bool
		valid() const;

		virtual std::vector<std::string>
		verify() const;

		virtual std::vector<std::string>
		dump() const;

	protected:
		ca_mgm::RWCOW_pointer<CRLDataImpl> m_impl;

		CRLData();

		std::vector<std::string>
		checkRevocationData(const std::map<std::string, RevocationEntry>& rd) const;

	};

}

#endif // LIMAL_CA_MGM_CRL_DATA_HPP
