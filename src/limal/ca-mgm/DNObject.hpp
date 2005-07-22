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

    class CAConfig;

    class RDNObject {
    public:
        RDNObject(const RDNObject& rdn);
        virtual ~RDNObject();

        RDNObject& operator=(const RDNObject& rdn);

        void   setRDNValue(const String& value);

        String getType() const;
        String getValue() const;

        virtual bool                 valid() const;
        virtual blocxx::StringArray  verify() const;

        virtual blocxx::StringArray  dump() const;

    protected:
        String type;
        String value;

        String prompt;
        blocxx::UInt32 min;
        blocxx::UInt32 max;

        RDNObject();
    };

    class DNObject {
    public:
        DNObject();
        DNObject(CAConfig* caConfig, Type type);
        DNObject(const blocxx::List<RDNObject> &dn);
        DNObject(const DNObject& dn);
        virtual ~DNObject();

        DNObject& operator=(const DNObject& dn);

        void            setDN(const blocxx::List<RDNObject> &dn);
        blocxx::List<RDNObject> getDN() const;

        virtual bool                 valid() const;
        virtual blocxx::StringArray  verify() const;
        
        virtual blocxx::StringArray  dump() const;

    private:
        blocxx::List<RDNObject> dn;

        blocxx::StringArray     checkRDNList(const blocxx::List<RDNObject>& list) const;

    };

}
}

#endif // LIMAL_CA_MGM_DN_OBJECT_HPP
