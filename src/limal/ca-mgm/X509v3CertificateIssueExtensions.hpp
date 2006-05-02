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

  File:       X509v3CertificateIssueExtensions.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#ifndef    LIMAL_CA_MGM_X509V_CERTIFICATE_ISSUE_EXTENSIONS_HPP
#define    LIMAL_CA_MGM_X509V_CERTIFICATE_ISSUE_EXTENSIONS_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/StringExtensions.hpp>
#include  <limal/ca-mgm/BitExtensions.hpp>
#include  <limal/ca-mgm/ExtendedKeyUsageExt.hpp>
#include  <limal/ca-mgm/BasicConstraintsExtension.hpp>
#include  <limal/ca-mgm/SubjectKeyIdentifierExtension.hpp>
#include  <limal/ca-mgm/SubjectKeyIdentifierExtension.hpp>
#include  <limal/ca-mgm/AuthorityKeyIdentifierGenerateExtension.hpp>
#include  <limal/ca-mgm/SubjectAlternativeNameExtension.hpp>
#include  <limal/ca-mgm/IssuerAlternativeNameExtension.hpp>
#include  <limal/ca-mgm/AuthorityInfoAccessExtension.hpp>
#include  <limal/ca-mgm/CRLDistributionPointsExtension.hpp>
#include  <limal/ca-mgm/CertificatePoliciesExtension.hpp>
#include  <blocxx/COWIntrusiveReference.hpp>

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

	class CA;
	class CAConfig;
	class X509v3CertificateIssueExtsImpl;
	
    /**
     * @brief Collection of X509v3 extension for signing a certificate
     *
     * This class includes a collection of X509v3 extension for signing a certificate
     */
	class X509v3CertificateIssueExts {
	public:
		X509v3CertificateIssueExts();
		X509v3CertificateIssueExts(CAConfig* caConfig, Type type);
		X509v3CertificateIssueExts(const X509v3CertificateIssueExts& extensions);
		virtual ~X509v3CertificateIssueExts();

#ifndef SWIG

		X509v3CertificateIssueExts&
		operator=(const X509v3CertificateIssueExts& extensions);

#endif
		
		void
		setNsBaseUrl(const NsBaseUrlExt &ext);
        
		NsBaseUrlExt
		getNsBaseUrl() const;

		void
		setNsRevocationUrl(const NsRevocationUrlExt &ext);
        
		NsRevocationUrlExt
		getNsRevocationUrl() const;

		void
		setNsCaRevocationUrl(const NsCaRevocationUrlExt &ext);
        
		NsCaRevocationUrlExt
		getNsCaRevocationUrl() const;

		void
		setNsRenewalUrl(const NsRenewalUrlExt &ext);
        
		NsRenewalUrlExt
		getNsRenewalUrl() const;

		void
		setNsCaPolicyUrl(const NsCaPolicyUrlExt &ext);
        
		NsCaPolicyUrlExt
		getNsCaPolicyUrl() const;

		void
		setNsSslServerName(const NsSslServerNameExt &ext);
        
		NsSslServerNameExt
		getNsSslServerName() const;

		void
		setNsComment(const NsCommentExt &ext);
        
		NsCommentExt
		getNsComment() const;

		void
		setNsCertType(const NsCertTypeExt &ext);
        
		NsCertTypeExt
		getNsCertType() const;

		void
		setKeyUsage(const KeyUsageExt &ext);
        
		KeyUsageExt
		getKeyUsage() const;

		void
		setBasicConstraints(const BasicConstraintsExt &ext);
        
		BasicConstraintsExt
		getBasicConstraints() const;

		void
		setExtendedKeyUsage(const ExtendedKeyUsageExt &ext);
        
		ExtendedKeyUsageExt
		getExtendedKeyUsage() const;

		void
		setSubjectKeyIdentifier(const SubjectKeyIdentifierExt &ext);
        
		SubjectKeyIdentifierExt
		getSubjectKeyIdentifier() const;

		void
		setAuthorityKeyIdentifier(const AuthorityKeyIdentifierGenerateExt &ext);
        
		AuthorityKeyIdentifierGenerateExt
		getAuthorityKeyIdentifier() const;

		void
		setSubjectAlternativeName(const SubjectAlternativeNameExt &ext);
        
		SubjectAlternativeNameExt
		getSubjectAlternativeName() const;
        
		void
		setIssuerAlternativeName(const IssuerAlternativeNameExt &ext);
        
		IssuerAlternativeNameExt
		getIssuerAlternativeName() const;
                                                                     
		void
		setAuthorityInfoAccess(const AuthorityInfoAccessExt &ext);
        
		AuthorityInfoAccessExt
		getAuthorityInfoAccess() const;

		void
		setCRLDistributionPoints(const CRLDistributionPointsExt &ext);
        
		CRLDistributionPointsExt
		getCRLDistributionPoints() const;

		void
		setCertificatePolicies(const CertificatePoliciesExt &ext);
        
		CertificatePoliciesExt
		getCertificatePolicies() const;

		void
		commit2Config(CA& ca, Type type) const;

		virtual bool
		valid() const;
        
		virtual blocxx::StringArray
		verify() const;

		virtual blocxx::StringArray
		dump() const;

	private:
		blocxx::COWIntrusiveReference<X509v3CertificateIssueExtsImpl> m_impl;

	};

}
}

#endif // LIMAL_CA_MGM_X509V_CERTIFICATE_ISSUE_EXTENSIONS_HPP
