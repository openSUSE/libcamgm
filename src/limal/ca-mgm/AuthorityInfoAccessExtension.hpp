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

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class AuthorityInfoAccessExtension : public ExtensionBase {
    public:
        enum AccessOIDType {
            OCSP,
            caIssuers,
            OID
        };

        AuthorityInfoAccessExtension();
        AuthorityInfoAccessExtension(const AuthorityInfoAccessExtension& extension);
        AuthorityInfoAccessExtension(CA& ca, Type type);
        virtual ~AuthorityInfoAccessExtension();

        AuthorityInfoAccessExtension& operator=(const AuthorityInfoAccessExtension& extension);
        
        /**
         * If AccessOIDType is OID, you have to provide a valid oid.
         * If AccessOIDType is OCSP or caIssuers the oid will receive 
         * no consideration.
         */
        void                   setAccessOIDType(AccessOIDType type, String oid=String());
        AccessOIDType          getAccessOIDType() const;

        /**
         * return an empty String if AccessOIDType is OCSP or caIssuer
         */
        String                 getAccessOID() const;

        void                   setLocation(List<LiteralValueBase> locationList);
        List<LiteralValueBase> getLocation() const;

        void                   addLocation(const LiteralValueBase& location);

        virtual void commit2Config(CA& ca, Type type);

    private:
        AccessOIDType          type;
        String                 accessIOD;

        List<LiteralValueBase> locList;
   
    };

}
}

#endif // LIMAL_CA_MGM_AUTHORITY_INFO_ACCESS_EXTENSION_HPP
