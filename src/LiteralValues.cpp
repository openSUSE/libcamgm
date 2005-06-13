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

  File:       LiteralValues.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/LiteralValues.hpp>

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;


LiteralValueBase::~LiteralValueBase()
{
}
        

void
LiteralValueBase::setValue(const String &value) 
{
    literalValue = value; 
}

blocxx::String
LiteralValueBase::getValue() const 
{
    return literalValue; 
}

//    protected:

LiteralValueBase::LiteralValueBase(const String &value) 
    : literalValue(value) 
{
}

LiteralValueBase::LiteralValueBase(const LiteralValueBase& value)
    : literalValue(value.literalValue)
{
}


LiteralValueBase&
LiteralValueBase::operator=(const LiteralValueBase& value)
{
    return *this;
}

// private

LiteralValueBase::LiteralValueBase()
    : literalValue(String())
{
};


// ##############################################################################


EmailLiteralValue::EmailLiteralValue(const String &value)
    : LiteralValueBase(value)
{
}

EmailLiteralValue::EmailLiteralValue(const EmailLiteralValue &value)
    : LiteralValueBase(value)
{
}

EmailLiteralValue::~EmailLiteralValue()
{
}


EmailLiteralValue&
EmailLiteralValue::operator=(const EmailLiteralValue& value)
{
    return *this;
}

void
EmailLiteralValue::setValue(const String &value)
{
    LiteralValueBase::setValue(value);
}

blocxx::String
EmailLiteralValue::getValue() const
{
    return LiteralValueBase::getValue();
}


// ##############################################################################

URILiteralValue::URILiteralValue(const String &value)
    : LiteralValueBase(value)
{
}

URILiteralValue::URILiteralValue(const URILiteralValue &value)
    : LiteralValueBase(value)
{
}

URILiteralValue::~URILiteralValue()
{
}


URILiteralValue&
URILiteralValue::operator=(const URILiteralValue& value)
{
    return *this;
}

void
URILiteralValue::setValue(const String &value)
{
    LiteralValueBase::setValue(value);
}

blocxx::String
URILiteralValue::getValue() const 
{
    return LiteralValueBase::getValue();
}


// ##############################################################################

DNSLiteralValue::DNSLiteralValue(const String &value)
    : LiteralValueBase(value)
{
}

DNSLiteralValue::DNSLiteralValue(const DNSLiteralValue &value)
    : LiteralValueBase(value)
{
}

DNSLiteralValue::~DNSLiteralValue()
{
}


DNSLiteralValue&
DNSLiteralValue::operator=(const DNSLiteralValue& value)
{
    return *this;
}

void
DNSLiteralValue::setValue(const String &value)
{
    LiteralValueBase::setValue(value);
}

blocxx::String
DNSLiteralValue::getValue() const
{
    return LiteralValueBase::getValue();
}


// ##############################################################################

RIDLiteralValue::RIDLiteralValue(const String &value)
    : LiteralValueBase(value)
{
}

RIDLiteralValue::RIDLiteralValue(const RIDLiteralValue &value)
    : LiteralValueBase(value)
{
}

RIDLiteralValue::~RIDLiteralValue()
{
}


RIDLiteralValue&
RIDLiteralValue::operator=(const RIDLiteralValue& value)
{
    return *this;
}


void
RIDLiteralValue::setValue(const String &value)
{
    LiteralValueBase::setValue(value);
}

blocxx::String
RIDLiteralValue::getValue() const
{
    return LiteralValueBase::getValue();
}


// ##############################################################################

IPLiteralValue::IPLiteralValue(const String &value)
    : LiteralValueBase(value)
{
}

IPLiteralValue::IPLiteralValue(const IPLiteralValue &value)
    : LiteralValueBase(value)
{
}

IPLiteralValue::~IPLiteralValue()
{
}


IPLiteralValue&
IPLiteralValue::operator=(const IPLiteralValue& value)
{
    return *this;
}

void
IPLiteralValue::setValue(const String &value)
{
    LiteralValueBase::setValue(value);
}

blocxx::String
IPLiteralValue::getValue() const
{
    return LiteralValueBase::getValue();
}

