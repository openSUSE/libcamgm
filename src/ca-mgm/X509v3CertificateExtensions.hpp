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

  File:       X509v3CertificateExtensions.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_X509V3_CERTIFICATE_EXTENSION_HPP
#define    LIMAL_CA_MGM_X509V3_CERTIFICATE_EXTENSION_HPP

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>
#include  <ca-mgm/StringExtensions.hpp>
#include  <ca-mgm/BitExtensions.hpp>
#include  <ca-mgm/ExtendedKeyUsageExt.hpp>
#include  <ca-mgm/BasicConstraintsExtension.hpp>
#include  <ca-mgm/SubjectKeyIdentifierExtension.hpp>
#include  <ca-mgm/SubjectKeyIdentifierExtension.hpp>
#include  <ca-mgm/AuthorityKeyIdentifierExtension.hpp>
#include  <ca-mgm/SubjectAlternativeNameExtension.hpp>
#include  <ca-mgm/IssuerAlternativeNameExtension.hpp>
#include  <ca-mgm/AuthorityInfoAccessExtension.hpp>
#include  <ca-mgm/CRLDistributionPointsExtension.hpp>
#include  <ca-mgm/CertificatePoliciesExtension.hpp>
#include <ca-mgm/PtrTypes.hpp>

namespace CA_MGM_NAMESPACE {

	class X509v3CertificateExtsImpl;
	
    /**
     * @brief Read-only data representation of X509 V3 Certificate Extensions
     */
	class X509v3CertificateExts {
					       		          		  public:
		X509v3CertificateExts(const X509v3CertificateExts& extensions);
		virtual ~X509v3CertificateExts();
		
#ifndef SWIG

		X509v3CertificateExts&
		operator=(const X509v3CertificateExts& extensions);

#endif
		
		NsBaseUrlExt
		getNsBaseUrl() const;
        
		NsRevocationUrlExt
		getNsRevocationUrl() const;
        
		NsCaRevocationUrlExt
		getNsCaRevocationUrl() const;
        
		NsRenewalUrlExt
		getNsRenewalUrl() const;
        
		NsCaPolicyUrlExt
		getNsCaPolicyUrl() const;
        
		NsSslServerNameExt
		getNsSslServerName() const;
        
		NsCommentExt
		getNsComment() const;
        
		NsCertTypeExt
		getNsCertType() const;
        
		KeyUsageExt
		getKeyUsage() const;
        
		BasicConstraintsExt
		getBasicConstraints() const;
        
		ExtendedKeyUsageExt
		getExtendedKeyUsage() const;
        
		SubjectKeyIdentifierExt
		getSubjectKeyIdentifier() const;
        
		AuthorityKeyIdentifierExt
		getAuthorityKeyIdentifier() const;
        
		SubjectAlternativeNameExt
		getSubjectAlternativeName() const;
        
		IssuerAlternativeNameExt
		getIssuerAlternativeName() const;
        
		AuthorityInfoAccessExt
		getAuthorityInfoAccess() const;
        
		CRLDistributionPointsExt
		getCRLDistributionPoints() const;
        
		CertificatePoliciesExt
		getCertificatePolicies() const;
        
		virtual bool
		valid() const;
        
		virtual std::vector<std::string>
		verify() const;

		virtual std::vector<std::string>
		dump() const;

	protected:
		ca_mgm::RWCOW_pointer<X509v3CertificateExtsImpl> m_impl;
		
		X509v3CertificateExts();

	};

}

#endif // LIMAL_CA_MGM_X509V3_CERTIFICATE_EXTENSION_HPP
