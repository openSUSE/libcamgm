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

  File:       X509v3CertificateExtensions_Priv.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include "X509v3CertificateExtensions_Priv.hpp"
#include "AuthorityKeyIdentifierExtension_Priv.hpp"
#include "LiteralValues_Priv.hpp"
#include <limal/Exception.hpp>

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include "X509v3CertificateExtensionsImpl.hpp"
#include "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;
using namespace blocxx;


X509v3CertificateExts_Priv::X509v3CertificateExts_Priv()
	: X509v3CertificateExts()
{}


X509v3CertificateExts_Priv::X509v3CertificateExts_Priv(STACK_OF(X509_EXTENSION) *extensions)
	: X509v3CertificateExts()
{
	// NsBaseUrlExt         nsBaseUrl;

	parseStringExt(extensions, NID_netscape_base_url, m_impl->nsBaseUrl);

	// NsRevocationUrlExt   nsRevocationUrl;

	parseStringExt(extensions, NID_netscape_revocation_url,
	               m_impl->nsRevocationUrl);

	// NsCaRevocationUrlExt nsCaRevocationUrl;

	parseStringExt(extensions, NID_netscape_ca_revocation_url,
	               m_impl->nsCaRevocationUrl);

	// NsRenewalUrlExt      nsRenewalUrl;

	parseStringExt(extensions, NID_netscape_renewal_url,
	               m_impl->nsRenewalUrl);

	// NsCaPolicyUrlExt     nsCaPolicyUrl;

	parseStringExt(extensions, NID_netscape_ca_policy_url,
	               m_impl->nsCaPolicyUrl);

	// NsSslServerNameExt   nsSslServerName;

	parseStringExt(extensions, NID_netscape_ssl_server_name,
	               m_impl->nsSslServerName);

	// NsCommentExt         nsComment;

	parseStringExt(extensions, NID_netscape_comment,
	               m_impl->nsComment);

	// KeyUsageExt   keyUsage;

	parseBitExt(extensions, NID_key_usage, m_impl->keyUsage);

	// NsCertTypeExt nsCertType;

	parseBitExt(extensions, NID_netscape_cert_type,
	            m_impl->nsCertType);

	// BasicConstraintsExt       basicConstraints;

	parseBasicConstraintsExt(extensions, m_impl->basicConstraints);

	// ExtendedKeyUsageExt       extendedKeyUsage;

	parseExtendedKeyUsageExt(extensions, m_impl->extendedKeyUsage);

	// SubjectKeyIdentifierExt   subjectKeyIdentifier;

	parseSubjectKeyIdentifierExt(extensions, m_impl->subjectKeyIdentifier);

	// AuthorityKeyIdentifierExt authorityKeyIdentifier;

	m_impl->authorityKeyIdentifier = AuthorityKeyIdentifierExt_Priv(extensions);

	// SubjectAlternativeNameExt subjectAlternativeName;

	parseSubjectAlternativeNameExt(extensions, m_impl->subjectAlternativeName);

	// IssuerAlternativeNameExt  issuerAlternativeName;

	parseIssuerAlternativeNameExt(extensions, m_impl->issuerAlternativeName);

	// AuthorityInfoAccessExt    authorityInfoAccess;

	parseAuthorityInfoAccessExt(extensions, m_impl->authorityInfoAccess);

	// CRLDistributionPointsExt  crlDistributionPoints;

	parseCRLDistributionPointsExt(extensions, m_impl->crlDistributionPoints);

	// CertificatePoliciesExt    certificatePolicies;

	parseCertificatePoliciesExt(extensions, m_impl->certificatePolicies);

}

X509v3CertificateExts_Priv::X509v3CertificateExts_Priv(const X509v3CertificateExts_Priv& extensions)
	: X509v3CertificateExts(extensions)
{}


X509v3CertificateExts_Priv::~X509v3CertificateExts_Priv()
{}

void
X509v3CertificateExts_Priv::setNsBaseUrl(const NsBaseUrlExt &ext)
{
	std::vector<blocxx::String> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(ValueException, r[0].c_str());
	}
	m_impl->nsBaseUrl = ext;
}

void
X509v3CertificateExts_Priv::setNsRevocationUrl(const NsRevocationUrlExt &ext)
{
	std::vector<blocxx::String> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(ValueException, r[0].c_str());
	}
	m_impl->nsRevocationUrl = ext;
}

void
X509v3CertificateExts_Priv::setNsCaRevocationUrl(const NsCaRevocationUrlExt &ext)
{
	std::vector<blocxx::String> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(ValueException, r[0].c_str());
	}
	m_impl->nsCaRevocationUrl = ext;
}

void
X509v3CertificateExts_Priv::setNsRenewalUrl(const NsRenewalUrlExt &ext)
{
	std::vector<blocxx::String> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(ValueException, r[0].c_str());
	}
	m_impl->nsRenewalUrl = ext;
}

void
X509v3CertificateExts_Priv::setNsCaPolicyUrl(const NsCaPolicyUrlExt &ext)
{
	std::vector<blocxx::String> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(ValueException, r[0].c_str());
	}
	m_impl->nsCaPolicyUrl = ext;
}

void
X509v3CertificateExts_Priv::setNsSslServerName(const NsSslServerNameExt &ext)
{
	std::vector<blocxx::String> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(ValueException, r[0].c_str());
	}
	m_impl->nsSslServerName = ext;
}

void
X509v3CertificateExts_Priv::setNsComment(const NsCommentExt &ext)
{
	std::vector<blocxx::String> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(ValueException, r[0].c_str());
	}
	m_impl->nsComment = ext;
}

void
X509v3CertificateExts_Priv::setNsCertType(const NsCertTypeExt &ext)
{
	std::vector<blocxx::String> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(ValueException, r[0].c_str());
	}
	m_impl->nsCertType = ext;
}

void
X509v3CertificateExts_Priv::setKeyUsage(const KeyUsageExt &ext)
{
	std::vector<blocxx::String> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(ValueException, r[0].c_str());
	}
	m_impl->keyUsage = ext;
}

void
X509v3CertificateExts_Priv::setBasicConstraints(const BasicConstraintsExt &ext)
{
	std::vector<blocxx::String> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(ValueException, r[0].c_str());
	}
	m_impl->basicConstraints = ext;
}

void
X509v3CertificateExts_Priv::setExtendedKeyUsage(const ExtendedKeyUsageExt &ext)
{
	std::vector<blocxx::String> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(ValueException, r[0].c_str());
	}
	m_impl->extendedKeyUsage = ext;
}

void
X509v3CertificateExts_Priv::setSubjectKeyIdentifier(const SubjectKeyIdentifierExt &ext)
{
	std::vector<blocxx::String> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(ValueException, r[0].c_str());
	}
	m_impl->subjectKeyIdentifier = ext;
}

void
X509v3CertificateExts_Priv::setAuthorityKeyIdentifier(const AuthorityKeyIdentifierExt &ext)
{
	std::vector<blocxx::String> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(ValueException, r[0].c_str());
	}
	m_impl->authorityKeyIdentifier = ext;
}

void
X509v3CertificateExts_Priv::setSubjectAlternativeName(const SubjectAlternativeNameExt &ext)
{
	std::vector<blocxx::String> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(ValueException, r[0].c_str());
	}
	m_impl->subjectAlternativeName = ext;
}

void
X509v3CertificateExts_Priv::setIssuerAlternativeName(const IssuerAlternativeNameExt &ext)
{
	std::vector<blocxx::String> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(ValueException, r[0].c_str());
	}
	m_impl->issuerAlternativeName = ext;
}

void
X509v3CertificateExts_Priv::setAuthorityInfoAccess(const AuthorityInfoAccessExt &ext)
{
	std::vector<blocxx::String> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(ValueException, r[0].c_str());
	}
	m_impl->authorityInfoAccess = ext;
}

void
X509v3CertificateExts_Priv::setCRLDistributionPoints(const CRLDistributionPointsExt &ext)
{
	std::vector<blocxx::String> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(ValueException, r[0].c_str());
	}
	m_impl->crlDistributionPoints = ext;
}

void
X509v3CertificateExts_Priv::setCertificatePolicies(const CertificatePoliciesExt &ext)
{
	std::vector<blocxx::String> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		BLOCXX_THROW(ValueException, r[0].c_str());
	}
	m_impl->certificatePolicies = ext;
}


//    private:
X509v3CertificateExts_Priv&
X509v3CertificateExts_Priv::operator=(const X509v3CertificateExts_Priv& extensions)
{
	if(this == &extensions) return *this;

	X509v3CertificateExts::operator=(extensions);

	return *this;
}

void
X509v3CertificateExts_Priv::parseStringExt(STACK_OF(X509_EXTENSION) * cert,
                                           int nid,
                                           StringExtension &ext)
{
	int crit = 0;

	ASN1_STRING *str = NULL;
	str = static_cast<ASN1_STRING *>(X509V3_get_d2i(cert, nid, &crit, NULL));

	if(str == NULL)
	{
		if(crit == -1)
		{
			// extension not found
			ext.setPresent(false);

			return;
		}
		else if(crit == -2)
		{
			// extension occurred more than once
			LOGIT_ERROR("Extension occurred more than once: " << nid);
			BLOCXX_THROW(SyntaxException,
			             Format(__("Extension occurred more than once: %1."),
			                    nid).c_str());
		}

		LOGIT_ERROR("Unable to parse the certificate (NID:" <<
		            nid << " Crit:" << crit << ")");
		BLOCXX_THROW(SyntaxException,
		             Format(__("Unable to parse the certificate (NID: %1 Crit: %2)."),
		                    nid, crit).c_str());
	}

	char *s = new char[str->length +1];
	memcpy(s, str->data, str->length);
	s[str->length] = '\0';

	ext.setValue(s);

	delete [] s;

	if(crit == 1)
	{
		ext.setCritical(true);
	}
	else
	{
		ext.setCritical(false);
	}

	ASN1_STRING_free(str);
}

void
X509v3CertificateExts_Priv::parseBitExt(STACK_OF(X509_EXTENSION)* cert,
                                        int nid,
                                        BitExtension &ext)
{
	int crit = 0;

	ASN1_BIT_STRING *bit = NULL;
	bit = static_cast<ASN1_BIT_STRING *>(X509V3_get_d2i(cert,
		nid,
		&crit,
		NULL));
	if(bit == NULL)
	{
		if(crit == -1)
		{
			// extension not found
			ext.setPresent(false);

			return;
		}
		else if(crit == -2)
		{
			// extension occurred more than once
			LOGIT_ERROR("Extension occurred more than once: " << nid);
			BLOCXX_THROW(SyntaxException,
			             Format(__("Extension occurred more than once: %1."),
			                    nid).c_str());
		}

		LOGIT_ERROR("Unable to parse the certificate (NID:" <<
		            nid << " Crit:" << crit << ")");
		BLOCXX_THROW(SyntaxException,
		             Format(__("Unable to parse the certificate (NID: %1 Crit: %2)."),
		                    nid, crit).c_str());
	}

	int    len = bit->length -1;
	uint32_t ret = 0;

	for(; len >= 0; --len)
	{
		int bits = bit->data[len];
		int shift = bits<<(len*8);
		ret |= shift;
	}

	ext.setValue(ret);

	if(crit == 1)
	{
		ext.setCritical(true);
	}
	else
	{
		ext.setCritical(false);
	}

	ASN1_STRING_free(bit);
}

void
X509v3CertificateExts_Priv::parseExtendedKeyUsageExt(STACK_OF(X509_EXTENSION)* cert,
                                                     ExtendedKeyUsageExt &ext)
{
	int crit = 0;

	EXTENDED_KEY_USAGE *eku = NULL;
	eku = static_cast<EXTENDED_KEY_USAGE *>(X509V3_get_d2i(cert,
		NID_ext_key_usage,
		&crit, NULL));
	if(eku == NULL)
	{
		if(crit == -1)
		{
			// extension not found
			ext.setPresent(false);

			return;
		}
		else if(crit == -2)
		{
			// extension occurred more than once
			LOGIT_ERROR("Extension occurred more than once");
			BLOCXX_THROW(SyntaxException,
			             __("Extension occurred more than once."));
		}

		LOGIT_ERROR("Unable to parse the certificate (" << "Crit:" << crit << ")");
		BLOCXX_THROW(SyntaxException,
		             Format(__("Unable to parse the certificate (Crit: %1)."),
		                    crit).c_str());
	}

	int i;
	ASN1_OBJECT *obj;
	char obj_tmp[80];
	StringList usageList;
	for(i = 0; i < sk_ASN1_OBJECT_num(eku); i++)
	{
		obj = sk_ASN1_OBJECT_value(eku, i);
		i2t_ASN1_OBJECT(obj_tmp, 80, obj);
		int nid = OBJ_txt2nid(obj_tmp);
		if(nid == 0)
		{
			usageList.push_back(obj_tmp);
		}
		else
		{
			usageList.push_back(String(OBJ_nid2sn(nid)));
		}
	}
	ext.setExtendedKeyUsage(usageList);

	if(crit == 1)
	{
		ext.setCritical(true);
	}
	else
	{
		ext.setCritical(false);
	}

	EXTENDED_KEY_USAGE_free(eku);
}

void
X509v3CertificateExts_Priv::parseBasicConstraintsExt(STACK_OF(X509_EXTENSION)* cert,
                                                     BasicConstraintsExt &ext)
{
	int crit = 0;

	BASIC_CONSTRAINTS *bs = NULL;
	bs = static_cast<BASIC_CONSTRAINTS *>(X509V3_get_d2i(cert,
		NID_basic_constraints,
		&crit, NULL));

	if(bs == NULL)
	{
		if(crit == -1)
		{
			// extension not found
			ext.setPresent(false);

			return;
		}
		else if(crit == -2)
		{
			// extension occurred more than once
			LOGIT_ERROR("Extension occurred more than once");
			BLOCXX_THROW(SyntaxException,
			             __("Extension occurred more than once."));
		}

		LOGIT_ERROR("Unable to parse the certificate (" << "Crit:" << crit << ")");
		BLOCXX_THROW(SyntaxException,
		             Format(__("Unable to parse the certificate (Crit: %1)."),
		                    crit).c_str());
	}

	bool  ca = false;
	Int32 pl = -1;

	if(bs->ca)
	{
		ca = true;

		if(bs->pathlen)
		{
			if(bs->pathlen->type != V_ASN1_NEG_INTEGER)
			{
				pl = ASN1_INTEGER_get(bs->pathlen);
			}
		}
	}

	ext.setBasicConstraints(ca, pl);

	if(crit == 1)
	{
		ext.setCritical(true);
	}
	else
	{
		ext.setCritical(false);
	}

	BASIC_CONSTRAINTS_free(bs);
}

void
X509v3CertificateExts_Priv::parseSubjectKeyIdentifierExt(STACK_OF(X509_EXTENSION) *cert,
                                                         SubjectKeyIdentifierExt &ext)
{
	int crit = 0;

	ASN1_OCTET_STRING *ski = NULL;
	ski = static_cast<ASN1_OCTET_STRING *>(X509V3_get_d2i(cert,
		NID_subject_key_identifier,
		&crit, NULL));

	if(ski == NULL)
	{
		if(crit == -1)
		{
			// extension not found
			ext.setPresent(false);

			return;
		}
		else if(crit == -2)
		{
			// extension occurred more than once
			LOGIT_ERROR("Extension occurred more than once");
			BLOCXX_THROW(SyntaxException,
			             __("Extension occurred more than once."));
		}

		LOGIT_ERROR("Unable to parse the certificate (" << "Crit:" << crit << ")");
		BLOCXX_THROW(SyntaxException,
		             Format(__("Unable to parse the certificate (Crit: %1)."),
		                    crit).c_str());
	}

	String s;

	for(int i = 0; i < ski->length; ++i)
	{
		String d;
		d.format("%02x", ski->data[i]);

		s += d;
		if( (i+1) < ski->length)
		{
			s += ":";
		}
	}

	ext.setSubjectKeyIdentifier(false, s);

	if(crit == 1)
	{
		ext.setCritical(true);
	}
	else
	{
		ext.setCritical(false);
	}

	ASN1_OCTET_STRING_free(ski);
}

void
X509v3CertificateExts_Priv::parseSubjectAlternativeNameExt(STACK_OF(X509_EXTENSION) *cert,
                                                           SubjectAlternativeNameExt &ext)
{
	int crit = 0;

	GENERAL_NAMES *gns = NULL;
	gns = static_cast<GENERAL_NAMES *>(X509V3_get_d2i(cert,
		NID_subject_alt_name,
		&crit, NULL));

	if(gns == NULL)
	{
		if(crit == -1)
		{
			// extension not found
			ext.setPresent(false);

			return;
		}
		else if(crit == -2)
		{
			// extension occurred more than once
			LOGIT_ERROR("Extension occurred more than once");
			BLOCXX_THROW(SyntaxException,
			             __("Extension occurred more than once."));

		}

		LOGIT_ERROR("Unable to parse the certificate (" << "Crit:" << crit << ")");
		BLOCXX_THROW(SyntaxException,
		             Format(__("Unable to parse the certificate (Crit: %1)."),
		                    crit).c_str());
	}

	int j;
	GENERAL_NAME *gen;
	std::list<LiteralValue> lvList;

	for(j = 0; j < sk_GENERAL_NAME_num(gns); j++)
	{
		gen = sk_GENERAL_NAME_value(gns, j);

		LiteralValue_Priv lv(gen);

		lvList.push_back(lv);
	}

	if(crit == 1)
	{
		ext.setCritical(true);
	}
	else
	{
		ext.setCritical(false);
	}

	if(!lvList.empty())
	{
		ext.setCopyEmail(false);
		ext.setAlternativeNameList(lvList);
	}
	else
	{
		ext.setPresent(false);
	}

	GENERAL_NAMES_free(gns);
}

void
X509v3CertificateExts_Priv::parseIssuerAlternativeNameExt(STACK_OF(X509_EXTENSION) *cert,
                                                          IssuerAlternativeNameExt &ext)
{
	int crit = 0;

	GENERAL_NAMES *gns = NULL;
	gns = static_cast<GENERAL_NAMES *>(X509V3_get_d2i(cert,
		NID_issuer_alt_name,
		&crit, NULL));

	if(gns == NULL)
	{
		if(crit == -1)
		{
			// extension not found
			ext.setPresent(false);

			return;
		}
		else if(crit == -2)
		{
			// extension occurred more than once
			LOGIT_ERROR("Extension occurred more than once");
			BLOCXX_THROW(SyntaxException,
			             __("Extension occurred more than once."));
		}

		LOGIT_ERROR("Unable to parse the certificate (" << "Crit:" << crit << ")");
		BLOCXX_THROW(SyntaxException,
		             Format(__("Unable to parse the certificate (Crit: %1)."),
		                    crit).c_str());
	}

	int j;
	GENERAL_NAME *gen;
	std::list<LiteralValue> lvList;

	for(j = 0; j < sk_GENERAL_NAME_num(gns); j++)
	{
		gen = sk_GENERAL_NAME_value(gns, j);

		LiteralValue_Priv lv(gen);

		lvList.push_back(lv);
	}

	if(crit == 1)
	{
		ext.setCritical(true);
	}
	else
	{
		ext.setCritical(false);
	}

	if(!lvList.empty())
	{
		ext.setCopyIssuer(false);
		ext.setAlternativeNameList(lvList);
	}
	else
	{
		ext.setPresent(false);
	}

	GENERAL_NAMES_free(gns);
}

void
X509v3CertificateExts_Priv::parseCRLDistributionPointsExt(STACK_OF(X509_EXTENSION) *cert,
                                                          CRLDistributionPointsExt &ext)
{
	int crit = 0;

	CRL_DIST_POINTS *cdps = NULL;
	cdps = static_cast<CRL_DIST_POINTS *>(X509V3_get_d2i(cert,
		NID_crl_distribution_points,
		&crit, NULL));

	if(cdps == NULL)
	{
		if(crit == -1)
		{
			// extension not found
			ext.setPresent(false);

			return;
		}
		else if(crit == -2)
		{
			// extension occurred more than once
			LOGIT_ERROR("Extension occurred more than once");
			BLOCXX_THROW(SyntaxException,
			             __("Extension occurred more than once."));

		}

		LOGIT_ERROR("Unable to parse the certificate (" << "Crit:" << crit << ")");
		BLOCXX_THROW(SyntaxException,
		             Format(__("Unable to parse the certificate (Crit: %1)."),
		                    crit).c_str());
	}

	DIST_POINT *point;
	int i, j;
	GENERAL_NAME *gen;
	std::list<LiteralValue> lvList;

	for(i = 0; i < sk_DIST_POINT_num(cdps); i++)
	{
		point = sk_DIST_POINT_value(cdps, i);
		if(point->distpoint)
		{
			if(point->distpoint->type == 0)
			{
				for(j = 0;
				    j < sk_GENERAL_NAME_num(point->distpoint->name.fullname);
				    j++)
				{
					gen = sk_GENERAL_NAME_value(point->distpoint->name.fullname,
					                            j);

					LiteralValue_Priv lv(gen);

					lvList.push_back(lv);
				}
			}
		}
	}

	ext.setCRLDistributionPoints(lvList);

	if(crit == 1)
	{
		ext.setCritical(true);
	}
	else
	{
		ext.setCritical(false);
	}

	CRL_DIST_POINTS_free(cdps);
}

void
X509v3CertificateExts_Priv::parseAuthorityInfoAccessExt(STACK_OF(X509_EXTENSION) *cert,
                                                        AuthorityInfoAccessExt &ext)
{
	int crit = 0;

	AUTHORITY_INFO_ACCESS *ainf = NULL;
	ainf = static_cast<AUTHORITY_INFO_ACCESS *>(X509V3_get_d2i(cert,
		NID_info_access,
		&crit, NULL));

	if(ainf == NULL)
	{
		if(crit == -1)
		{
			// extension not found
			ext.setPresent(false);

			return;
		}
		else if(crit == -2)
		{
			// extension occurred more than once
			LOGIT_ERROR("Extension occurred more than once");
			BLOCXX_THROW(SyntaxException,
			             __("Extension occurred more than once."));
		}

		LOGIT_ERROR("Unable to parse the certificate (" << "Crit:" << crit << ")");
		BLOCXX_THROW(SyntaxException,
		             Format(__("Unable to parse the certificate (Crit: %1)."), crit).c_str());
	}


	ACCESS_DESCRIPTION *desc;
	int i;
	char objtmp[80];
	std::list<AuthorityInformation> infolist;


	for(i = 0; i < sk_ACCESS_DESCRIPTION_num(ainf); i++)
	{
		desc = sk_ACCESS_DESCRIPTION_value(ainf, i);

		LiteralValue_Priv lv(desc->location);

		if(!lv.valid())
		{
			LOGIT_ERROR("Invalid location in authorityInfoAccess");
			BLOCXX_THROW(SyntaxException,
			             __("Invalid location in authorityInfoAccess."));
		}

		String method;

		i2t_ASN1_OBJECT(objtmp, sizeof objtmp, desc->method);

		int nid = OBJ_txt2nid(objtmp);

		if(nid == 0)
		{
			method = String(objtmp);
		}
		else
		{
			method = String(OBJ_nid2sn(nid));
		}

		AuthorityInformation ai(method, lv);

		infolist.push_back(ai);
	}

	ext.setAuthorityInformation(infolist);

	if(crit == 1)
	{
		ext.setCritical(true);
	}
	else
	{
		ext.setCritical(false);
	}

	AUTHORITY_INFO_ACCESS_free(ainf);
}

void
X509v3CertificateExts_Priv::parseCertificatePoliciesExt(STACK_OF(X509_EXTENSION) *cert,
                                                        CertificatePoliciesExt &ext)
{
	int crit = 0;

	CERTIFICATEPOLICIES *cps = NULL;
	cps = static_cast<CERTIFICATEPOLICIES *>(X509V3_get_d2i(cert,
		NID_certificate_policies,
		&crit, NULL));

	if(cps == NULL)
	{
		if(crit == -1) {
			// extension not found
			ext.setPresent(false);

			return;
		}
		else if(crit == -2)
		{
			// extension occurred more than once
			LOGIT_ERROR("Extension occurred more than once");
			BLOCXX_THROW(SyntaxException,
			             __("Extension occurred more than once."));
		}

		LOGIT_ERROR("Unable to parse the certificate (" << "Crit:" << crit << ")");
		BLOCXX_THROW(SyntaxException,
		             Format(__("Unable to parse the certificate (Crit: %1)."),
		                    crit).c_str());
	}

	int i;
	POLICYINFO *pinfo;
	char obj_tmp[256];
	std::list<CertificatePolicy> policies;

	/* First print out the policy OIDs */
	for(i = 0; i < sk_POLICYINFO_num(cps); i++)
	{
		pinfo = sk_POLICYINFO_value(cps, i);

		i2t_ASN1_OBJECT(obj_tmp, sizeof obj_tmp, pinfo->policyid);

		CertificatePolicy cp(obj_tmp);

		if(pinfo->qualifiers)
		{
			POLICYQUALINFO *qualinfo;
			int j;
			StringList cpsURI;
			std::list<UserNotice> noticeList;
			UserNotice un;
			char *s;

			for(j = 0; j < sk_POLICYQUALINFO_num(pinfo->qualifiers); j++)
			{
				qualinfo = sk_POLICYQUALINFO_value(pinfo->qualifiers, j);

				switch(OBJ_obj2nid(qualinfo->pqualid))
				{
				case NID_id_qt_cps:
					s = new char[qualinfo->d.cpsuri->length +1];
					memcpy(s, qualinfo->d.cpsuri->data, qualinfo->d.cpsuri->length);
					s[qualinfo->d.cpsuri->length] = '\0';

					cpsURI.push_back(String(s));
					delete [] s;
					break;
				case NID_id_qt_unotice:
					int k;
					un = UserNotice();

					if(qualinfo->d.usernotice->noticeref)
					{
						NOTICEREF *ref;
						std::list<int32_t> numberList;

						ref = qualinfo->d.usernotice->noticeref;

						for(k = 0; k < sk_ASN1_INTEGER_num(ref->noticenos); k++)
						{
							ASN1_INTEGER *num;
							char *tmp;

							num = sk_ASN1_INTEGER_value(ref->noticenos, k);
							tmp = i2s_ASN1_INTEGER(NULL, num);

							numberList.push_back(String(tmp).toInt32());

							OPENSSL_free(tmp);
						}
						s = new char[ref->organization->length +1];
						memcpy(s, ref->organization->data, ref->organization->length);
						s[ref->organization->length] = '\0';

						un.setOrganizationNotice(s, numberList);

						delete [] s;
					}
					if(qualinfo->d.usernotice->exptext)
					{
						s = new char[qualinfo->d.usernotice->exptext->length +1];
						memcpy(s, qualinfo->d.usernotice->exptext->data,
						       qualinfo->d.usernotice->exptext->length);
						s[qualinfo->d.usernotice->exptext->length] = '\0';

						un.setExplicitText(s);

						delete [] s;
					}
					noticeList.push_back(un);
					break;
				default:
					i2t_ASN1_OBJECT(obj_tmp, sizeof obj_tmp, qualinfo->pqualid);

					LOGIT_INFO("Unknown Qualifier: " << obj_tmp);
					break;
				}
			}
			cp.setCpsURI(cpsURI);
			cp.setUserNoticeList(noticeList);
		}
		policies.push_back(cp);
	}

	ext.setPolicies(policies);

	if(crit == 1)
	{
		ext.setCritical(true);
	}
	else
	{
		ext.setCritical(false);
	}

	CERTIFICATEPOLICIES_free(cps);
}

}
