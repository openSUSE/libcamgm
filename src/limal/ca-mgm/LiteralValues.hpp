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

  File:       LiteralValues.hpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#ifndef    LIMAL_CA_MGM_LITERAL_VALUES_HPP
#define    LIMAL_CA_MGM_LITERAL_VALUES_HPP

#include  <limal/ca-mgm/config.h>
#include  <limal/ca-mgm/CommonData.hpp>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class LiteralValueBase {
    public:
        LiteralValueBase(const String &value = String());
        LiteralValueBase(const LiteralValueBase& value);

        LiteralValueBase& operator=(const LiteralValueBase& value);
        virtual ~LiteralValueBase();
        

        virtual void   setValue(const String &value);
        virtual String getValue() const;

        virtual bool                valid() const;
        virtual blocxx::StringArray verify() const;

    private:
        String literalValue;

    };

    class EmailLiteralValue : public LiteralValueBase {
    public:
        EmailLiteralValue(const String &value = String());
        EmailLiteralValue(const EmailLiteralValue &value);
        virtual ~EmailLiteralValue();

        EmailLiteralValue& operator=(const EmailLiteralValue& value);

        virtual void   setValue(const String &value);
        virtual String getValue() const ;

        virtual bool                valid() const;
        virtual blocxx::StringArray verify() const;
    };

    class URILiteralValue : public LiteralValueBase {
    public:
        URILiteralValue(const String &value = String());
        URILiteralValue(const URILiteralValue &value);
        virtual ~URILiteralValue();

        URILiteralValue& operator=(const URILiteralValue& value);

        virtual void   setValue(const String &value);
        virtual String getValue() const ;

        virtual bool                valid() const;
        virtual blocxx::StringArray verify() const;
    };

    class DNSLiteralValue : public LiteralValueBase {
    public:
        DNSLiteralValue(const String &value = String());
        DNSLiteralValue(const DNSLiteralValue &value);
        virtual ~DNSLiteralValue();

        DNSLiteralValue& operator=(const DNSLiteralValue& value);

        virtual void   setValue(const String &value);
        virtual String getValue() const ;

        virtual bool                valid() const;
        virtual blocxx::StringArray verify() const;
    };

    class RIDLiteralValue : public LiteralValueBase {
    public:
        RIDLiteralValue(const String &value = String());
        RIDLiteralValue(const RIDLiteralValue &value);
        virtual ~RIDLiteralValue();

        RIDLiteralValue& operator=(const RIDLiteralValue& value);

        virtual void   setValue(const String &value);
        virtual String getValue() const ;

        virtual bool                valid() const;
        virtual blocxx::StringArray verify() const;
    };

    class IPLiteralValue : public LiteralValueBase {
    public:
        IPLiteralValue(const String &value = String());
        IPLiteralValue(const IPLiteralValue &value);
        virtual ~IPLiteralValue();

        IPLiteralValue& operator=(const IPLiteralValue& value);

        virtual void   setValue(const String &value);
        virtual String getValue() const ;

        virtual bool                valid() const;
        virtual blocxx::StringArray verify() const;
    };

}
}

#endif // LIMAL_CA_MGM_LITERAL_VALUES_HPP
