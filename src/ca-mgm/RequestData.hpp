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

  File:       RequestData.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    CA_MGM_REQUEST_DATA_HPP
#define    CA_MGM_REQUEST_DATA_HPP

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>
#include  <ca-mgm/X509v3RequestExtensions.hpp>
#include  <ca-mgm/DNObject.hpp>
#include  <ca-mgm/ByteBuffer.hpp>
#include <ca-mgm/PtrTypes.hpp>


namespace CA_MGM_NAMESPACE {

	class RequestDataImpl;

    /**
     * @brief Read-only data representation of a request
     *
     * This class is a read-only data representation of a request
     */
	class RequestData {
	public:
		RequestData(const RequestData& data);
		virtual ~RequestData();

#ifndef SWIG

		RequestData&
		operator=(const RequestData& data);

#endif

		uint32_t
		getVersion() const;

		uint32_t
		getKeysize() const;

		DNObject
		getSubjectDN() const;

		KeyAlg
		getKeyAlgorithm() const;

		ca_mgm::ByteBuffer
		getPublicKey() const;

		SigAlg
		getSignatureAlgorithm() const;

		ca_mgm::ByteBuffer
		getSignature() const;

		X509v3RequestExts
		getExtensions() const;

		std::string
		getChallengePassword() const;

		std::string
		getUnstructuredName() const;

		/**
		 * Return the Request in a human readable format
		 * (Format may change)
		 */
		std::string
		getRequestAsText() const;

		/**
		 * Return the Request extensions in a human readable format
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
		ca_mgm::RWCOW_pointer<RequestDataImpl> m_impl;

		RequestData();

	};

}

#endif // CA_MGM_REQUEST_DATA_HPP
