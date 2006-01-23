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

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/ca-mgm/X509v3CertificateIssueExtensions.hpp>
#include  <blocxx/COWIntrusiveReference.hpp>

namespace LIMAL_NAMESPACE
{
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

		CertificateIssueData&
		operator=(const CertificateIssueData& data);

		void
		setCertifyPeriode(time_t start, time_t end);
        
		time_t
		getStartDate() const;
        
		time_t
		getEndDate() const;

		/**
		 * Returns the start date as string for openssl (GMT)
		 */ 
		blocxx::String
		getStartDateAsString() const;

		/**
		 * Returns the end date as string for openssl (GMT)
		 */ 
		blocxx::String
		getEndDateAsString() const;

		void
		setMessageDigest(MD md);
        
		MD
		getMessageDigest() const;

		void
		setExtensions(const X509v3CertificateIssueExts& ext);
        
		X509v3CertificateIssueExts
		getExtensions() const;

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
		virtual blocxx::StringArray
		verify() const;

		/**
		 * Return the content of this object for debugging
		 */
		virtual blocxx::StringArray
		dump() const;

	private:
		blocxx::COWIntrusiveReference<CertificateIssueDataImpl> m_impl;
    	

	};

}
}
#endif //LIMAL_CA_MGM_CERTIFICATE_ISSUE_DATA_HPP
