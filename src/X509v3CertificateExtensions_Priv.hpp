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

  File:       X509v3CertificateExtensions_Priv.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    CA_MGM_X509V3_CERTIFICATE_EXTENSION_PRIV_HPP
#define    CA_MGM_X509V3_CERTIFICATE_EXTENSION_PRIV_HPP

#include  <ca-mgm/config.h>
#include  <ca-mgm/CommonData.hpp>
#include  <ca-mgm/X509v3CertificateExtensions.hpp>
#include  <openssl/x509.h>


namespace CA_MGM_NAMESPACE {

class X509v3CertificateExts_Priv : public X509v3CertificateExts {
public:
	X509v3CertificateExts_Priv();
	X509v3CertificateExts_Priv(STACK_OF(X509_EXTENSION) *extensions);
	X509v3CertificateExts_Priv(const X509v3CertificateExts_Priv& extensions);
	virtual ~X509v3CertificateExts_Priv();

	void
	setNsBaseUrl(const NsBaseUrlExt &ext);

	void
	setNsRevocationUrl(const NsRevocationUrlExt &ext);

	void
	setNsCaRevocationUrl(const NsCaRevocationUrlExt &ext);

	void
	setNsRenewalUrl(const NsRenewalUrlExt &ext);

	void
	setNsCaPolicyUrl(const NsCaPolicyUrlExt &ext);

	void
	setNsSslServerName(const NsSslServerNameExt &ext);

	void
	setNsComment(const NsCommentExt &ext);

	void
	setNsCertType(const NsCertTypeExt &ext);

	void
	setKeyUsage(const KeyUsageExt &ext);

	void
	setBasicConstraints(const BasicConstraintsExt &ext);

	void
	setExtendedKeyUsage(const ExtendedKeyUsageExt &ext);

	void
	setSubjectKeyIdentifier(const SubjectKeyIdentifierExt &ext);

	void
	setAuthorityKeyIdentifier(const AuthorityKeyIdentifierExt &ext);

	void
	setSubjectAlternativeName(const SubjectAlternativeNameExt &ext);

	void
	setIssuerAlternativeName(const IssuerAlternativeNameExt &ext);

	void
	setAuthorityInfoAccess(const AuthorityInfoAccessExt &ext);

	void
	setCRLDistributionPoints(const CRLDistributionPointsExt &ext);

	void
	setCertificatePolicies(const CertificatePoliciesExt &ext);

private:

	X509v3CertificateExts_Priv&
	operator=(const X509v3CertificateExts_Priv& extensions);

	void
	parseStringExt(STACK_OF(X509_EXTENSION)* cert,
	               int nid, StringExtension &ext);

	void
	parseBitExt(STACK_OF(X509_EXTENSION)* cert,
	            int nid, BitExtension &ext);

	void
	parseExtendedKeyUsageExt(STACK_OF(X509_EXTENSION)* cert,
	                         ExtendedKeyUsageExt &ext);

	void
	parseBasicConstraintsExt(STACK_OF(X509_EXTENSION)* cert,
	                         BasicConstraintsExt &ext);

	void
	parseSubjectKeyIdentifierExt(STACK_OF(X509_EXTENSION) *cert,
	                             SubjectKeyIdentifierExt &ext);

	void
	parseSubjectAlternativeNameExt(STACK_OF(X509_EXTENSION) *cert,
	                               SubjectAlternativeNameExt &ext);

	void
	parseIssuerAlternativeNameExt(STACK_OF(X509_EXTENSION) *cert,
	                              IssuerAlternativeNameExt &ext);

	void
	parseCRLDistributionPointsExt(STACK_OF(X509_EXTENSION) *cert,
	                              CRLDistributionPointsExt &ext);

	void
	parseAuthorityInfoAccessExt(STACK_OF(X509_EXTENSION) *cert,
	                            AuthorityInfoAccessExt &ext);

	void
	parseCertificatePoliciesExt(STACK_OF(X509_EXTENSION) *cert,
	                            CertificatePoliciesExt &ext);
};

}

#endif // CA_MGM_X509V3_CERTIFICATE_EXTENSION_PRIV_HPP
