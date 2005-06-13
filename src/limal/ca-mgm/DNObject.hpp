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

  File:       DNObject.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_DN_OBJECT_HPP
#define    LIMAL_CA_MGM_DN_OBJECT_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class RDNObject {
    public:
        RDNObject();
        RDNObject(const String& type, const String& value);
        RDNObject(const RDNObject& rdn);
        virtual ~RDNObject();

        RDNObject& operator=(const RDNObject& rdn);

        void   setType(const String& type);
        void   setValue(const String& value);

        String getType() const;
        String getValue() const;

    private:
        String type;
        String value;

    };

    class DNObject {
    public:
        DNObject();
        DNObject(const blocxx::List<RDNObject> &dn);
        DNObject(const DNObject& dn);
        virtual ~DNObject();

        DNObject& operator=(const DNObject& dn);

        void            setDN(const blocxx::List<RDNObject> &dn);
        blocxx::List<RDNObject> getDN() const;
        
    private:
        blocxx::List<RDNObject> dn;

    };

}
}

#endif // LIMAL_CA_MGM_DN_OBJECT_HPP
