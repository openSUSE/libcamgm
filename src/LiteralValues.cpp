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
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

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
    if(this == &value) return *this;

    literalValue = value.literalValue;

    return *this;
}

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


bool
LiteralValueBase::valid() const
{
    return false;
}

blocxx::StringArray
LiteralValueBase::verify() const
{
    StringArray result;
    result.append(String("This is the base object. This should never happen"));
    return result;
}


// ##############################################################################

inline static ValueCheck initEmailLiteralValueCheck() {
    ValueCheck checkEmail =
        ValueCheck(new ValueRegExCheck("^[^@]+@[^@]+$"));

    return checkEmail;
}

EmailLiteralValue::EmailLiteralValue(const String &value)
    : LiteralValueBase(value)
{
    ValueCheck check = initEmailLiteralValueCheck();
    if(!check.isValid(getValue())) {
        BLOCXX_THROW(limal::ValueException,
                     Format("invalid email address(%1) in EmailLiteralValue", getValue()).c_str());
    }
}

EmailLiteralValue::EmailLiteralValue(const EmailLiteralValue &value)
    : LiteralValueBase(value)
{}

EmailLiteralValue::~EmailLiteralValue()
{}


EmailLiteralValue&
EmailLiteralValue::operator=(const EmailLiteralValue& value)
{
    if(this == &value) return *this;
    
    LiteralValueBase::operator=(value);

    return *this;
}

void
EmailLiteralValue::setValue(const String &value)
{
    ValueCheck check = initEmailLiteralValueCheck();
    if(!check.isValid(value)) {
        BLOCXX_THROW(limal::ValueException,
                     Format("invalid email address(%1)", value).c_str());
    }
    LiteralValueBase::setValue(value);
}

blocxx::String
EmailLiteralValue::getValue() const
{
    return LiteralValueBase::getValue();
}

bool
EmailLiteralValue::valid() const
{
    ValueCheck check = initEmailLiteralValueCheck();
    if(!check.isValid(getValue())) {
        return false;
    }
    return true;
}

blocxx::StringArray
EmailLiteralValue::verify() const
{
    blocxx::StringArray result;
    
    ValueCheck check = initEmailLiteralValueCheck();
    if(!check.isValid(getValue())) {
        result.append(Format("invalid email address(%1) in EmailLiteralValue", getValue()).toString());
    }
}


// ##############################################################################


ValueCheck initURILiteralValueCheck() {
    ValueCheck checkEmail =
        ValueCheck(new ValueRegExCheck("^(([^:/?#]+)://)?([^/?#]*)?([^?#]*)?(\\?([^#]*))?(#(.*))?"  ));

    return checkEmail;
}

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
    if(this == &value) return *this;
    
    LiteralValueBase::operator=(value);

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

bool
URILiteralValue::valid() const
{
    // Fixme: add check
    return false;
}

blocxx::StringArray
URILiteralValue::verify() const
{
    // Fixme: add check
    StringArray result;
    result.append(String("This is the base object. This should never happen"));
    return result;
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
    if(this == &value) return *this;
    
    LiteralValueBase::operator=(value);

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

bool
DNSLiteralValue::valid() const
{
    // Fixme: add check
    return false;
}

blocxx::StringArray
DNSLiteralValue::verify() const
{
    // Fixme: add check
    StringArray result;
    result.append(String("This is the base object. This should never happen"));
    return result;
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
    if(this == &value) return *this;
    
    LiteralValueBase::operator=(value);

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

bool
RIDLiteralValue::valid() const
{
    // Fixme: add check
    return false;
}

blocxx::StringArray
RIDLiteralValue::verify() const
{
    // Fixme: add check
    StringArray result;
    result.append(String("This is the base object. This should never happen"));
    return result;
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
    if(this == &value) return *this;
    
    LiteralValueBase::operator=(value);

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

bool
IPLiteralValue::valid() const
{
    // Fixme: add check
    return false;
}

blocxx::StringArray
IPLiteralValue::verify() const
{
    // Fixme: add check
    StringArray result;
    result.append(String("This is the base object. This should never happen"));
    return result;
}
