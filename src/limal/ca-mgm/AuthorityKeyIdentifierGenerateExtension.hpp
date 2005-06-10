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

  File:       AuthorityKeyIdentifierGenerateExtension.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_AUTHORITY_KEY_IDENTIFIER_GENERATE_EXTENSION_HPP
#define    LIMAL_CA_MGM_AUTHORITY_KEY_IDENTIFIER_GENERATE_EXTENSION_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class AuthorityKeyIdentifierGenerateExtension : public ExtensionBase {
    public:

        enum KeyID {
            none,
            normal,
            always
        };
        
        enum Issuer {
            none,
            normal,
            always
        };

        AuthorityKeyIdentifierExtension();
        AuthorityKeyIdentifierExtension(CA& ca, Type type);
        AuthorityKeyIdentifierExtension(KeyID kid, Issuer iss);
        AuthorityKeyIdentifierExtension(const AuthorityKeyIdentifierExtension& extension);
        virtual ~AuthorityKeyIdentifierExtension();

        AuthorityKeyIdentifierExtension& operator=(const AuthorityKeyIdentifierExtension& extension);

        void           setKeyID(KeyID kid);
        KeyID          getKeyID() const;

        void           setIssuer(Issuer iss);
        Issuer         getIssuer() const;

        virtual void   commit2Config(CA& ca, Type type);

    private:
        KeyID  keyid;
        Issuer issuer; 

    };

}
}

#endif // LIMAL_CA_MGM_AUTHORITY_KEY_IDENTIFIER_GENERATE_EXTENSION_HPP
