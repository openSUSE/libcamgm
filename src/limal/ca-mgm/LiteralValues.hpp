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

    class LiteralValue {
    public:
        LiteralValue();
        LiteralValue(const String &type, const String &value);
        LiteralValue(const String& value);
        LiteralValue(const LiteralValue& value);

        LiteralValue& operator=(const LiteralValue& value);
        virtual ~LiteralValue();

        virtual void   setLiteral(const String &type, const String &value);
        virtual void   setValue(const String &value);
        virtual String getType() const;
        virtual String getValue() const;

        virtual bool                valid() const;
        virtual blocxx::StringArray verify() const;

        virtual blocxx::StringArray  dump() const;

        virtual String              toString() const;

    private:
        String literalType;
        String literalValue;

    };

}
}

#endif // LIMAL_CA_MGM_LITERAL_VALUES_HPP
