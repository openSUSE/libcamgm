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

  File:       AuthorityKeyIdentifierExtension.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_AUTHORITY_KEY_IDENTIFIER_EXTENSION_HPP
#define    LIMAL_CA_MGM_AUTHORITY_KEY_IDENTIFIER_EXTENSION_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/ExtensionBase.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class AuthorityKeyIdentifierExtension : public ExtensionBase {
    public:

        AuthorityKeyIdentifierExtension();
        AuthorityKeyIdentifierExtension(const AuthorityKeyIdentifierExtension& extension);
        virtual ~AuthorityKeyIdentifierExtension();

        AuthorityKeyIdentifierExtension& operator=(const AuthorityKeyIdentifierExtension& extension);

        String         getKeyID() const;
        String         getDirName() const;
        String         getSerial() const;

        virtual bool                 valid() const;  
        virtual blocxx::StringArray  verify() const; 
        
    protected:

        String keyid;
        String DirName; // oder issuer?
        String serial;  // String?

    private:
        virtual void commit2Config(CA& ca, Type type) const;
    };

}
}

#endif // LIMAL_CA_MGM_AUTHORITY_KEY_IDENTIFIER_EXTENSION_HPP
