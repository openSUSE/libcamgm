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

  File:       X509v3CRLExtensions_Priv.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  "X509v3CRLExtensions_Priv.hpp"
#include  "LiteralValues_Priv.hpp"
#include  <ca-mgm/Exception.hpp>

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include  "X509v3CRLExtensionsImpl.hpp"
#include  "Utils.hpp"
#include  "AuthorityKeyIdentifierExtension_Priv.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;


X509v3CRLExts_Priv::X509v3CRLExts_Priv()
	: X509v3CRLExts()
{}

X509v3CRLExts_Priv::X509v3CRLExts_Priv(STACK_OF(X509_EXTENSION) *extensions)
	: X509v3CRLExts()
{
	// AuthorityKeyIdentifierExt authorityKeyIdentifier;

	m_impl->authorityKeyIdentifier = AuthorityKeyIdentifierExt_Priv(extensions);

	// IssuerAlternativeNameExt  issuerAlternativeName;

	parseIssuerAlternativeNameExt(extensions,
	                              m_impl->issuerAlternativeName);

}

X509v3CRLExts_Priv::X509v3CRLExts_Priv(const X509v3CRLExts_Priv& extensions)
	: X509v3CRLExts(extensions)
{}


X509v3CRLExts_Priv::~X509v3CRLExts_Priv()
{}

void
X509v3CRLExts_Priv::setAuthorityKeyIdentifier(const AuthorityKeyIdentifierExt &ext)
{
	std::vector<std::string> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		CA_MGM_THROW(ca_mgm::ValueException, r[0].c_str());
	}
	m_impl->authorityKeyIdentifier = ext;
}

void
X509v3CRLExts_Priv::setIssuerAlternativeName(const IssuerAlternativeNameExt &ext)
{
	std::vector<std::string> r = ext.verify();
	if(!r.empty())
	{
		LOGIT_ERROR(r[0]);
		CA_MGM_THROW(ca_mgm::ValueException, r[0].c_str());
	}
	m_impl->issuerAlternativeName = ext;
}


//  private:
X509v3CRLExts_Priv&
X509v3CRLExts_Priv::operator=(const X509v3CRLExts_Priv& extensions)
{
	if(this == &extensions) return *this;

	X509v3CRLExts::operator=(extensions);

	return *this;
}

void
X509v3CRLExts_Priv::parseIssuerAlternativeNameExt(STACK_OF(X509_EXTENSION) *cert,
                                                  IssuerAlternativeNameExt &ext)
{
	int crit = 0;

	GENERAL_NAMES *gns = NULL;
	gns = static_cast<GENERAL_NAMES *>(X509V3_get_d2i(cert,
		NID_issuer_alt_name,
		&crit,
		NULL));

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
		ext.setCopyIssuer(false);
		ext.setAlternativeNameList(lvList);
	}
	else
	{
		ext.setPresent(false);
	}

	GENERAL_NAMES_free(gns);
}

}
