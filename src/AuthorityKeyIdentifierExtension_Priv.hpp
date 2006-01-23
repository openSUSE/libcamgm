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

  File:       AuthorityKeyIdentifierExtension_Priv.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_AUTHORITY_KEY_IDENTIFIER_EXTENSION_PRIV_HPP
#define    LIMAL_CA_MGM_AUTHORITY_KEY_IDENTIFIER_EXTENSION_PRIV_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/AuthorityKeyIdentifierExtension.hpp>
#include  <openssl/x509.h>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

	class AuthorityKeyIdentifierExt_Priv : public AuthorityKeyIdentifierExt {
	public:

		AuthorityKeyIdentifierExt_Priv();
		AuthorityKeyIdentifierExt_Priv(STACK_OF(X509_EXTENSION)* extensions);
		AuthorityKeyIdentifierExt_Priv(const AuthorityKeyIdentifierExt_Priv& extension);
		virtual ~AuthorityKeyIdentifierExt_Priv();
        
		AuthorityKeyIdentifierExt_Priv&
		operator=(const AuthorityKeyIdentifierExt_Priv& extension);

	};

}
}

#endif // LIMAL_CA_MGM_AUTHORITY_KEY_IDENTIFIER_EXTENSION_PRIV_HPP
