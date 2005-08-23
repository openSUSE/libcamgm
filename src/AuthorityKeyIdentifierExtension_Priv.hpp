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

    class AuthorityKeyIdentifierExtension_Priv : public AuthorityKeyIdentifierExtension {
    public:

        AuthorityKeyIdentifierExtension_Priv();
        AuthorityKeyIdentifierExtension_Priv(X509* cert);
        AuthorityKeyIdentifierExtension_Priv(X509_CRL* crl);
        AuthorityKeyIdentifierExtension_Priv(const AuthorityKeyIdentifierExtension_Priv& extension);
        virtual ~AuthorityKeyIdentifierExtension_Priv();
        
        AuthorityKeyIdentifierExtension_Priv&
        operator=(const AuthorityKeyIdentifierExtension_Priv& extension);

        void           setKeyID(const String& kid);
        void           setDirName(const String& dirName);
        void           setSerial(const String& serial);
       
    };

}
}

#endif // LIMAL_CA_MGM_AUTHORITY_KEY_IDENTIFIER_EXTENSION_PRIV_HPP
