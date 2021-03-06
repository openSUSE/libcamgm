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

  File:       X509v3CertificateExtsImpl.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    CA_MGM_X509V3_CERTIFICATE_EXTS_IMPL_HPP
#define    CA_MGM_X509V3_CERTIFICATE_EXTS_IMPL_HPP

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



namespace CA_MGM_NAMESPACE {

class X509v3CertificateExtsImpl
{
public:
	X509v3CertificateExtsImpl()
		: nsBaseUrl(NsBaseUrlExt()),
		nsRevocationUrl(NsRevocationUrlExt()),
		nsCaRevocationUrl(NsCaRevocationUrlExt()),
		nsRenewalUrl(NsRenewalUrlExt()),
		nsCaPolicyUrl(NsCaPolicyUrlExt()),
		nsSslServerName(NsSslServerNameExt()),
		nsComment(NsCommentExt()),
		keyUsage(KeyUsageExt()),
		nsCertType(NsCertTypeExt()),
		basicConstraints(BasicConstraintsExt()),
		extendedKeyUsage(ExtendedKeyUsageExt()),
		subjectKeyIdentifier(SubjectKeyIdentifierExt()),
		authorityKeyIdentifier(AuthorityKeyIdentifierExt()),
		subjectAlternativeName(SubjectAlternativeNameExt()),
		issuerAlternativeName(IssuerAlternativeNameExt()),
		authorityInfoAccess(AuthorityInfoAccessExt()),
		crlDistributionPoints(CRLDistributionPointsExt()),
		certificatePolicies(CertificatePoliciesExt())
	{}

	X509v3CertificateExtsImpl(const X509v3CertificateExtsImpl& impl)
		: nsBaseUrl(impl.nsBaseUrl),
		nsRevocationUrl(impl.nsRevocationUrl),
		nsCaRevocationUrl(impl.nsCaRevocationUrl),
		nsRenewalUrl(impl.nsRenewalUrl),
		nsCaPolicyUrl(impl.nsCaPolicyUrl),
		nsSslServerName(impl.nsSslServerName),
		nsComment(impl.nsComment),
		keyUsage(impl.keyUsage),
		nsCertType(impl.nsCertType),
		basicConstraints(impl.basicConstraints),
		extendedKeyUsage(impl.extendedKeyUsage),
		subjectKeyIdentifier(impl.subjectKeyIdentifier),
		authorityKeyIdentifier(impl.authorityKeyIdentifier),
		subjectAlternativeName(impl.subjectAlternativeName),
		issuerAlternativeName(impl.issuerAlternativeName),
		authorityInfoAccess(impl.authorityInfoAccess),
		crlDistributionPoints(impl.crlDistributionPoints),
		certificatePolicies(impl.certificatePolicies)
	{}

	~X509v3CertificateExtsImpl() {}

	X509v3CertificateExtsImpl* clone() const
	{
		return new X509v3CertificateExtsImpl(*this);
	}

		/* std::string extensions */

	NsBaseUrlExt              nsBaseUrl;
	NsRevocationUrlExt        nsRevocationUrl;
	NsCaRevocationUrlExt      nsCaRevocationUrl;
	NsRenewalUrlExt           nsRenewalUrl;
	NsCaPolicyUrlExt          nsCaPolicyUrl;
	NsSslServerNameExt        nsSslServerName;
	NsCommentExt              nsComment;

		/* Bit std::strings */
	KeyUsageExt               keyUsage;
	NsCertTypeExt             nsCertType;

	BasicConstraintsExt       basicConstraints;
	ExtendedKeyUsageExt       extendedKeyUsage;
	SubjectKeyIdentifierExt   subjectKeyIdentifier;
	AuthorityKeyIdentifierExt authorityKeyIdentifier;
	SubjectAlternativeNameExt subjectAlternativeName;
	IssuerAlternativeNameExt  issuerAlternativeName;

	AuthorityInfoAccessExt    authorityInfoAccess;
	CRLDistributionPointsExt  crlDistributionPoints;
	CertificatePoliciesExt    certificatePolicies;
};

}
#endif   /* CA_MGM_X509V3_CERTIFICATE_EXTS_IMPL_HPP */
