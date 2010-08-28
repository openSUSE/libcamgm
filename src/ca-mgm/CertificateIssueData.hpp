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

  File:       CertificateIssueData.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#ifndef    LIMAL_CA_MGM_CERTIFICATE_ISSUE_DATAHPP
#define    LIMAL_CA_MGM_CERTIFICATE_ISSUE_DATAHPP

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>
#include  <ca-mgm/CA.hpp>
#include  <ca-mgm/X509v3CertificateIssueExtensions.hpp>
#include <ca-mgm/PtrTypes.hpp>

namespace CA_MGM_NAMESPACE
{

	class CertificateIssueDataImpl;
	
    /**
     * @brief Data representation for signing a certificate
     *
     * This class is a data representation for signing a certificate
     */
	class CertificateIssueData {
	public:
		CertificateIssueData();

		/**
		 * Initialize this object with the defaults of the CA 
		 * and Type
		 */
		CertificateIssueData(CAConfig* caConfig, Type type);

		CertificateIssueData(const CertificateIssueData& data);

		virtual ~CertificateIssueData();

#ifndef SWIG

		CertificateIssueData&
		operator=(const CertificateIssueData& data);

#endif
		
		void
		setCertifyPeriode(time_t start, time_t end);
        
		time_t
		getStartDate() const;
        
		time_t
		getEndDate() const;

		/**
		 * Returns the start date as string for openssl (GMT)
		 */ 
		std::string
		getStartDateAsString() const;

		/**
		 * Returns the end date as string for openssl (GMT)
		 */ 
		std::string
		getEndDateAsString() const;

		void
		setMessageDigest(MD md);
        
		MD
		getMessageDigest() const;

		void
		setExtensions(const X509v3CertificateIssueExts& ext);
        
		X509v3CertificateIssueExts
		getExtensions() const;

		X509v3CertificateIssueExts&
		extensions();

		/** 
		 * Write memory data to config file
		 */
		void
		commit2Config(CA& ca, Type type) const;

		/**
		 * Check if this object is valid
		 *
		 * @return true if this object is valid, otherwise false
		 */
		virtual bool
		valid() const;

		/**
		 * Verify this object and return an Array with all
		 * error messages.
		 *
		 * @return Array with error messages. If this Array is empty this
		 * object is valid
		 */
		virtual std::vector<std::string>
		verify() const;

		/**
		 * Return the content of this object for debugging
		 */
		virtual std::vector<std::string>
		dump() const;

	private:
		ca_mgm::RWCOW_pointer<CertificateIssueDataImpl> m_impl;
    	

	};

}
#endif //LIMAL_CA_MGM_CERTIFICATE_ISSUE_DATA_HPP
