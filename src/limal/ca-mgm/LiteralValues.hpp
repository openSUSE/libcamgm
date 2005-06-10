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
#include  <limal/ca-mgm/CommonData.h>

namespace LIMAL_NAMESPACE {

namespace CA_MGM_NAMESPACE {

    class LiteralValueBase {
    public:
        virtual ~LiteralValueBase();
        

        virtual void   setValue(const String &value) = 0;
        virtual String getValue() const = 0;

    protected:
        LiteralValueBase(const String &value) : literalValue(value);
        LiteralValueBase(const LiteralValueBase& value);

        LiteralValueBase& operator=(const LiteralValueBase& value);

    private:
        String literalValue;

        LiteralValueBase() : literalValue(String());

    };

    class EmailLiteralValue : public LiteralValueBase {
    public:
        EmailLiteralValue(const String &value);
        EmailLiteralValue(const EmailLiteralValue &value);
        virtual ~EmailLiteralValue();

        EmailLiteralValue& operator=(const EmailLiteralValue& value);

        virtual void   setValue(const String &value);
        virtual String getValue() const ;
    };

    class URILiteralValue : public LiteralValueBase {
    public:
        URILiteralValue(const String &value);
        URILiteralValue(const URILiteralValue &value);
        virtual ~URILiteralValue();

        URILiteralValue& operator=(const URILiteralValue& value);

        virtual void   setValue(const String &value);
        virtual String getValue() const ;
    };

    class DNSLiteralValue : public LiteralValueBase {
    public:
        DNSLiteralValue(const String &value);
        DNSLiteralValue(const DNSLiteralValue &value);
        virtual ~DNSLiteralValue();

        DNSLiteralValue& operator=(const DNSLiteralValue& value);

        virtual void   setValue(const String &value);
        virtual String getValue() const ;
    };

    class RIDLiteralValue : public LiteralValueBase {
    public:
        RIDLiteralValue(const String &value);
        RIDLiteralValue(const RIDLiteralValue &value);
        virtual ~RIDLiteralValue();

        RIDLiteralValue& operator=(const RIDLiteralValue& value);

        virtual void   setValue(const String &value);
        virtual String getValue() const ;
    };

    class IPLiteralValue : public LiteralValueBase {
    public:
        IPLiteralValue(const String &value);
        IPLiteralValue(const IPLiteralValue &value);
        virtual ~IPLiteralValue();

        IPLiteralValue& operator=(const IPLiteralValue& value);

        virtual void   setValue(const String &value);
        virtual String getValue() const ;
    };

}
}

#endif // LIMAL_CA_MGM_LITERAL_VALUES_HPP
