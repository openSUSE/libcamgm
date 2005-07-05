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

  File:       AuthorityInfoAccessExtension.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_AUTHORITY_INFO_ACCESS_EXTENSION_HPP
#define    LIMAL_CA_MGM_AUTHORITY_INFO_ACCESS_EXTENSION_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>
#include  <limal/ca-mgm/LiteralValues.hpp>
#include  <limal/ca-mgm/ExtensionBase.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class CA;

    class AuthorityInformation {

    public:
        AuthorityInformation();
        AuthorityInformation(const AuthorityInformation& ai);
        AuthorityInformation(const String &accessOID, 
                             const LiteralValue& location);

        AuthorityInformation&   operator=(const AuthorityInformation& ai);

        void                    setAuthorityInformation(const String &accessOID, 
                                                        const LiteralValue& location);

        String                  getAccessOID() const;
        LiteralValue            getLocation() const;

        bool                    valid() const;
        blocxx::StringArray     verify() const;

    private:
        String                  accessOID;
        LiteralValue            location;

    };

    class AuthorityInfoAccessExtension : public ExtensionBase {
    public:

        AuthorityInfoAccessExtension();
        AuthorityInfoAccessExtension(const AuthorityInfoAccessExtension& extension);
        AuthorityInfoAccessExtension(CA& ca, Type type);
        virtual ~AuthorityInfoAccessExtension();

        AuthorityInfoAccessExtension& operator=(const AuthorityInfoAccessExtension& extension);
        
        void
        setAuthorityInformation(const blocxx::List<AuthorityInformation>& infolist);

        blocxx::List<AuthorityInformation>
        getAuthorityInformation() const;

        virtual void commit2Config(CA& ca, Type type) const;

        virtual bool                 valid() const; 
        virtual blocxx::StringArray  verify() const;

    private:
        blocxx::List<AuthorityInformation> info;
   
    };

}
}

#endif // LIMAL_CA_MGM_AUTHORITY_INFO_ACCESS_EXTENSION_HPP
