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
#ifndef    LIMAL_CA_MGM_REQUEST_DATA_HPP
#define    LIMAL_CA_MGM_REQUEST_DATA_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/X509v3RequestExtensions.hpp>
#include  <limal/ca-mgm/DNObject.hpp>
#include  <limal/ByteBuffer.hpp>
#include  <blocxx/COWIntrusiveReference.hpp>


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
		
		blocxx::UInt32
		getVersion() const;
        
		blocxx::UInt32
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
        
		String
		getChallengePassword() const;
        
		String
		getUnstructuredName() const;

		/**
		 * Return the Request in a human readable format
		 * (Format may change)
		 */
		String
		getRequestAsText() const;

		/**
		 * Return the Request extensions in a human readable format
		 * (Format may change)
		 */
		String
		getExtensionsAsText() const;
    	
		virtual bool
		valid() const;
        
		virtual blocxx::StringArray
		verify() const;

		virtual blocxx::StringArray
		dump() const;

	protected:
		blocxx::COWIntrusiveReference<RequestDataImpl> m_impl;
    	
		RequestData();

	};

}

#endif // LIMAL_CA_MGM_REQUEST_DATA_HPP
