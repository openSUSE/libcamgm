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

  File:       CertificateData.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_CERTIFICATE_DATA_HPP
#define    LIMAL_CA_MGM_CERTIFICATE_DATA_HPP

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>
#include  <ca-mgm/X509v3CertificateExtensions.hpp>
#include  <ca-mgm/DNObject.hpp>
#include  <ca-mgm/ByteBuffer.hpp>
#include <ca-mgm/PtrTypes.hpp>

namespace CA_MGM_NAMESPACE {

	class CertificateDataImpl;

    /**
     * @brief Read-only data representation of a certificate
     *
     * This class is a read-only data representation of a certificate
     */
	class CertificateData {
	public:
		CertificateData(const CertificateData& data);

		virtual ~CertificateData();

#ifndef SWIG

		CertificateData&
		operator=(const CertificateData& data);

#endif

		uint32_t
		getVersion() const;

		std::string
		getSerial() const;

		time_t
		getStartDate() const;

		time_t
		getEndDate() const;

		DNObject
		getIssuerDN() const;

		DNObject
		getSubjectDN() const;

		uint32_t
		getKeysize() const;

		KeyAlg
		getPublicKeyAlgorithm() const;

		std::string
		getPublicKeyAlgorithmAsString() const;

		ca_mgm::ByteBuffer
		getPublicKey() const;

		SigAlg
		getSignatureAlgorithm() const;

		std::string
		getSignatureAlgorithmAsString() const;

		ca_mgm::ByteBuffer
		getSignature() const;

		std::string
		getFingerprint() const;

		X509v3CertificateExts
		getExtensions() const;

		/**
		 * Return the Certificate data as human readable text.
		 * (Format may change)
		 */
		std::string
		getCertificateAsText() const;

		/**
		 * Return the Certificate extensions as human readable text.
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
		CertificateData();


		ca_mgm::RWCOW_pointer<CertificateDataImpl> m_impl;
	};

}

#endif // LIMAL_CA_MGM_CERTIFICATE_DATA_HPP
