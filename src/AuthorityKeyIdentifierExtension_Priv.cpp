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

  File:       AuthorityKeyIdentifierExtension_Priv.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  "AuthorityKeyIdentifierExtension_Priv.hpp"

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include "Utils.hpp"

namespace CA_MGM_NAMESPACE
{

using namespace ca_mgm;

AuthorityKeyIdentifierExt_Priv::AuthorityKeyIdentifierExt_Priv()
	: AuthorityKeyIdentifierExt()
{
}

AuthorityKeyIdentifierExt_Priv::AuthorityKeyIdentifierExt_Priv(STACK_OF(X509_EXTENSION)* extensions)
	: AuthorityKeyIdentifierExt()
{
	int crit = 0;

	AUTHORITY_KEYID *aki = NULL;
	aki = static_cast<AUTHORITY_KEYID *>(X509V3_get_d2i(extensions,
		NID_authority_key_identifier,
		&crit, NULL));

	if(aki == NULL)
	{
		if(crit == -1)
		{
			// extension not found
			setPresent(false);

			return;
		}
		else if(crit == -2)
		{
			// extension occurred more than once
			LOGIT_ERROR("Extension occurred more than once");
			CA_MGM_THROW(ca_mgm::SyntaxException,
			             "Extension occurred more than once");
		}

		LOGIT_ERROR("Unable to parse the certificate (" << "Crit:" << crit << ")");
		CA_MGM_THROW(ca_mgm::SyntaxException,
		             str::form("Unable to parse the certificate (Crit: %d)",
		                    crit).c_str());
	}

	if(aki->keyid)
	{
		std::string tmpKeyID;

		for(int i = 0; i < aki->keyid->length; ++i)
		{
			tmpKeyID += str::form( "%02x", aki->keyid->data[i]);
			if( (i+1) < aki->keyid->length)
			{
				tmpKeyID += ":";
			}
		}
		setKeyID(tmpKeyID);
	}

	if(aki->issuer)
	{
		int j;
		GENERAL_NAME *gen;
		std::string tmpDirName;

		for(j = 0; j < sk_GENERAL_NAME_num(aki->issuer); j++)
		{
			gen = sk_GENERAL_NAME_value(aki->issuer, j);

			if(gen->type == GEN_DIRNAME)
			{
				char oline[256];
				X509_NAME_oneline(gen->d.dirn, oline, 256);

				tmpDirName += oline;

				if( (j+1) < sk_GENERAL_NAME_num(aki->issuer) )
				{
					tmpDirName += '\n';
				}
			}
		}
		setDirName(tmpDirName);
	}

	if(aki->serial)
	{
		std::string tmpSerial;

		for(int i = 0; i < aki->serial->length; ++i)
		{
			tmpSerial += str::form( "%02x", aki->serial->data[i]);
			if( (i+1) < aki->serial->length)
			{
				tmpSerial += ":";
			}
		}
		setSerial(tmpSerial);
	}

	setPresent(true);

	AUTHORITY_KEYID_free(aki);
}

AuthorityKeyIdentifierExt_Priv::AuthorityKeyIdentifierExt_Priv(const AuthorityKeyIdentifierExt_Priv& extension)
	: AuthorityKeyIdentifierExt(extension)
{}

AuthorityKeyIdentifierExt_Priv::~AuthorityKeyIdentifierExt_Priv()
{}

AuthorityKeyIdentifierExt_Priv&
AuthorityKeyIdentifierExt_Priv::operator=(const AuthorityKeyIdentifierExt_Priv& extension)
{
	if(this == &extension) return *this;

	AuthorityKeyIdentifierExt::operator=(extension);

	return *this;
}


}
