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

  File:       AuthorityKeyIdentifierExtension_Int.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_AUTHORITY_KEY_IDENTIFIER_EXTENSION_INT_HPP
#define    LIMAL_CA_MGM_AUTHORITY_KEY_IDENTIFIER_EXTENSION_INT_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/AuthorityKeyIdentifierExtension.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class AuthorityKeyIdentifierExtension_Int : public AuthorityKeyIdentifierExtension {
    public:

        AuthorityKeyIdentifierExtension_Int();
        AuthorityKeyIdentifierExtension_Int(X509* cert);
        AuthorityKeyIdentifierExtension_Int(X509_CRL* crl);
        virtual ~AuthorityKeyIdentifierExtension_Int();
        
        void           setKeyID(const String& kid);
        void           setDirName(const String& dirName);
        void           setSerial(const String& serial);
    private:
        AuthorityKeyIdentifierExtension_Int(const AuthorityKeyIdentifierExtension_Int& extension);
        
        AuthorityKeyIdentifierExtension_Int&
        operator=(const AuthorityKeyIdentifierExtension_Int& extension);
    };

}
}

#endif // LIMAL_CA_MGM_AUTHORITY_KEY_IDENTIFIER_EXTENSION_INT_HPP
