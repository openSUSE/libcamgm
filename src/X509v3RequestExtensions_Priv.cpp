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

  File:       X509v3RequestExtensions_Priv.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  "X509v3RequestExtensions_Priv.hpp"
#include  "LiteralValues_Priv.hpp"
#include  <ca-mgm/Exception.hpp>

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include  "X509v3RequestExtensionsImpl.hpp"
#include  "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;

X509v3RequestExts_Priv::X509v3RequestExts_Priv()
	: X509v3RequestExts()
{}

X509v3RequestExts_Priv::X509v3RequestExts_Priv(STACK_OF(X509_EXTENSION)* extensions)
	: X509v3RequestExts()
{
	// NsSslServerNameExt   nsSslServerName;

	parseStringExt(extensions, NID_netscape_ssl_server_name,
	               m_impl->nsSslServerName);

	// NsCommentExt         nsComment;

	parseStringExt(extensions, NID_netscape_comment,
	               m_impl->nsComment);

	// KeyUsageExt   keyUsage;

	parseBitExt(extensions, NID_key_usage, m_impl->keyUsage);

	// NsCertTypeExt nsCertType;

	parseBitExt(extensions, NID_netscape_cert_type, m_impl->nsCertType);

	// BasicConstraintsExt       basicConstraints;

	parseBasicConstraintsExt(extensions, m_impl->basicConstraints);

	// ExtendedKeyUsageExt             extendedKeyUsage;

	parseExtendedKeyUsageExt(extensions, m_impl->extendedKeyUsage);

	// SubjectKeyIdentifierExt   subjectKeyIdentifier;

	parseSubjectKeyIdentifierExt(extensions,
	                             m_impl->subjectKeyIdentifier);

	// SubjectAlternativeNameExt subjectAlternativeName;

	parseSubjectAlternativeNameExt(extensions,
	                               m_impl->subjectAlternativeName);

}

X509v3RequestExts_Priv::X509v3RequestExts_Priv(const X509v3RequestExts_Priv& extensions)
	: X509v3RequestExts(extensions)
{}


X509v3RequestExts_Priv::~X509v3RequestExts_Priv()
{}


//    private:
X509v3RequestExts_Priv&
X509v3RequestExts_Priv::operator=(const X509v3RequestExts_Priv& extensions)
{
	if(this == &extensions) return *this;

	X509v3RequestExts::operator=(extensions);

	return *this;
}

void
X509v3RequestExts_Priv::parseStringExt(STACK_OF(X509_EXTENSION) * cert,
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
			CA_MGM_THROW(ca_mgm::SyntaxException,
			             str::form(__("Extension occurred more than once: %1."),
			                    nid).c_str());
		}

		LOGIT_ERROR("Unable to parse the certificate (NID:" << nid <<
		            " Crit:" << crit << ")");
		CA_MGM_THROW(ca_mgm::SyntaxException,
		             str::form(__("Unable to parse the certificate (NID: %1 Crit: %2)."),
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
X509v3RequestExts_Priv::parseBitExt(STACK_OF(X509_EXTENSION)* cert,
                                    int nid,
                                    BitExtension &ext)
{
	int crit = 0;

	ASN1_BIT_STRING *bit = NULL;
	bit = static_cast<ASN1_BIT_STRING *>(X509V3_get_d2i(cert, nid, &crit, NULL));

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
			CA_MGM_THROW(ca_mgm::SyntaxException,
			             str::form(__("Extension occurred more than once: %1."),
			                    nid).c_str());
		}

		LOGIT_ERROR("Unable to parse the certificate (NID:" << nid <<
		            " Crit:" << crit << ")");
		CA_MGM_THROW(ca_mgm::SyntaxException,
		             str::form(__("Unable to parse the certificate (NID: %1 Crit: %2)."),
		                    nid, crit).c_str());
	}

	int len = bit->length -1;
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
X509v3RequestExts_Priv::parseExtendedKeyUsageExt(STACK_OF(X509_EXTENSION)* cert,
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
			CA_MGM_THROW(ca_mgm::SyntaxException,
			             __("Extension occurred more than once."));
		}

		LOGIT_ERROR("Unable to parse the certificate (" << "Crit:" << crit << ")");
		CA_MGM_THROW(ca_mgm::SyntaxException,
		             str::form(__("Unable to parse the certificate (Crit: %1)."),
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
			usageList.push_back(std::string(OBJ_nid2sn(nid)));
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
X509v3RequestExts_Priv::parseBasicConstraintsExt(STACK_OF(X509_EXTENSION)* cert,
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
			CA_MGM_THROW(ca_mgm::SyntaxException,
			             __("Extension occurred more than once."));
		}

		LOGIT_ERROR("Unable to parse the certificate (" << "Crit:" << crit << ")");
		CA_MGM_THROW(ca_mgm::SyntaxException,
		             str::form(__("Unable to parse the certificate (Crit: %1)."),
		                    crit).c_str());
	}

	bool  ca = false;
	int32_t pl = -1;

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
X509v3RequestExts_Priv::parseSubjectKeyIdentifierExt(STACK_OF(X509_EXTENSION) *cert,
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
			CA_MGM_THROW(ca_mgm::SyntaxException,
			             __("Extension occurred more than once."));

		}

		LOGIT_ERROR("Unable to parse the certificate (" << "Crit:" << crit << ")");
		CA_MGM_THROW(ca_mgm::SyntaxException,
		             str::form(__("Unable to parse the certificate (Crit: %1)."),
		                    crit).c_str());
	}

	std::string s;

	for(int i = 0; i < ski->length; ++i)
	{
		s += str::form( "%02x", ski->data[i]);
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
X509v3RequestExts_Priv::parseSubjectAlternativeNameExt(STACK_OF(X509_EXTENSION) *cert,
                                                       SubjectAlternativeNameExt &ext)
{
	int crit = 0;

	GENERAL_NAMES *gns = NULL;
	gns = static_cast<GENERAL_NAMES *>(X509V3_get_d2i(cert, NID_subject_alt_name, &crit, NULL));

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
			CA_MGM_THROW(ca_mgm::SyntaxException,
			             __("Extension occurred more than once."));
		}

		LOGIT_ERROR("Unable to parse the certificate (" << "Crit:" << crit << ")");
		CA_MGM_THROW(ca_mgm::SyntaxException,
		             str::form(__("Unable to parse the certificate (Crit: %1)."),
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

}
