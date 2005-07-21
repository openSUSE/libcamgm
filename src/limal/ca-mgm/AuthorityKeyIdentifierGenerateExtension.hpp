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
#include  <limal/ca-mgm/ExtensionBase.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class CA;
    class CAConfig;

    class AuthorityKeyIdentifierGenerateExtension : public ExtensionBase {
    public:

        enum KeyID {
            KeyID_none,
            KeyID_normal,
            KeyID_always
        };
        
        enum Issuer {
            Issuer_none,
            Issuer_normal,
            Issuer_always
        };

        AuthorityKeyIdentifierGenerateExtension();
        AuthorityKeyIdentifierGenerateExtension(CAConfig* caConfig, Type type);
        AuthorityKeyIdentifierGenerateExtension(KeyID kid, Issuer iss);
        AuthorityKeyIdentifierGenerateExtension(const AuthorityKeyIdentifierGenerateExtension& extension);
        virtual ~AuthorityKeyIdentifierGenerateExtension();

        AuthorityKeyIdentifierGenerateExtension& 
        operator=(const AuthorityKeyIdentifierGenerateExtension& extension);

        void           setKeyID(KeyID kid);
        KeyID          getKeyID() const;

        void           setIssuer(Issuer iss);
        Issuer         getIssuer() const;

        virtual void   commit2Config(CA& ca, Type type) const;

        virtual bool                 valid() const;  
        virtual blocxx::StringArray  verify() const; 

        virtual blocxx::StringArray  dump() const;

    private:
        KeyID  keyid;
        Issuer issuer; 

    };

}
}

#endif // LIMAL_CA_MGM_AUTHORITY_KEY_IDENTIFIER_GENERATE_EXTENSION_HPP
