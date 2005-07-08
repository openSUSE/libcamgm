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

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

LiteralValue::LiteralValue() 
    : literalType(String()), literalValue(String()) 
{}

LiteralValue::LiteralValue(const String &type, const String &value) 
    : literalType(type), literalValue(value) 
{
    StringArray r = this->verify();
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

LiteralValue::LiteralValue(const String& value)
    : literalType(String()), literalValue(String())
{
    StringArray   sp   = PerlRegEx("^(\\w+):(.*)$").capture(value);
    
    if(sp[1].equalsIgnoreCase("email")) {
        literalType  = sp[1];
        literalValue = sp[2];
    } else if(sp[1].equalsIgnoreCase("URI")) {
        literalType  = sp[1];
        literalValue = sp[2];
    } else if(sp[1].equalsIgnoreCase("DNS")) {
        literalType  = sp[1];
        literalValue = sp[2];
    } else if(sp[1].equalsIgnoreCase("RID")) {
        literalType  = sp[1];
        literalValue = sp[2];
    } else if(sp[1].equalsIgnoreCase("IP")) {
        literalType  = sp[1];
        literalValue = sp[2];
    } else {
        LOGIT_DEBUG("unknown type: "<< sp[1] << " = " << sp[2]);
        BLOCXX_THROW(limal::ValueException , "unknown type");
    }
}

LiteralValue::LiteralValue(const LiteralValue& value)
    : literalType(value.literalType), literalValue(value.literalValue)
{}


LiteralValue&
LiteralValue::operator=(const LiteralValue& value)
{
    if(this == &value) return *this;

    literalValue = value.literalValue;
    literalType = value.literalType;

    return *this;
}

LiteralValue::~LiteralValue()
{}
        

void
LiteralValue::setLiteral(const String &type, const String &value)
{
    String dType = literalType;
    String dValue = literalValue;

    literalType = type;
    literalValue = value;

    StringArray r = this->verify();
    if(!r.empty()) {
        literalType = dType;
        literalValue = dValue;
        
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

void
LiteralValue::setValue(const String &value) 
{
    String dValue = literalValue;
    
    literalValue = value; 

    StringArray r = this->verify();
    if(!r.empty()) {
        literalValue = dValue;
        
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

blocxx::String
LiteralValue::getValue() const 
{
    return literalValue; 
}

blocxx::String
LiteralValue::getType() const
{
    return literalType;
}

bool
LiteralValue::valid() const
{
    if(literalType == "email") {
        ValueCheck check = initEmailCheck();
        if(!check.isValid(literalValue)) {
            LOGIT_DEBUG("Wrong LiteralValue for type 'email': " << literalValue);
            return false;
        }
    } else if(literalType == "URI") {
        ValueCheck check = initURICheck();
        if(!check.isValid(literalValue)) {
            LOGIT_DEBUG("Wrong LiteralValue for type 'URI': " << literalValue);
            return false;
        }
    } else if(literalType == "DNS") {
        ValueCheck check = initDNSCheck();
        if(!check.isValid(literalValue)) {
            LOGIT_DEBUG("Wrong LiteralValue for type 'DNS': " << literalValue);
            return false;
        }
    } else if(literalType == "RID") {
        ValueCheck check = initOIDCheck();
        if(!check.isValid(literalValue)) {
            LOGIT_DEBUG("Wrong LiteralValue for type 'RID': " << literalValue);
            return false;
        }
    } else if(literalType == "IP") {
        ValueCheck check = initIPCheck();
        if(!check.isValid(literalValue)) {
            LOGIT_DEBUG("Wrong LiteralValue for type 'IP': " << literalValue);
            return false;
        }
    } else {
        LOGIT_DEBUG("Unknown Type in LiteralValue: " << literalType);
        return false;
    }
    return true;
}

blocxx::StringArray
LiteralValue::verify() const
{
    StringArray result;

    if(literalType == "email") {
        ValueCheck check = initEmailCheck();
        if(!check.isValid(literalValue)) {
            LOGIT_DEBUG("Wrong LiteralValue for type 'email': " << literalValue);
            result.append(Format("Wrong LiteralValue for type 'email': %1", literalValue).toString());
        }
    } else if(literalType == "URI") {
        ValueCheck check = initURICheck();
        if(!check.isValid(literalValue)) {
            LOGIT_DEBUG("Wrong LiteralValue for type 'URI': " << literalValue);
            result.append(Format("Wrong LiteralValue for type 'URI': %1", literalValue).toString());
        }
    } else if(literalType == "DNS") {
        ValueCheck check = initDNSCheck();
        if(!check.isValid(literalValue)) {
            LOGIT_DEBUG("Wrong LiteralValue for type 'DNS': " << literalValue);
            result.append(Format("Wrong LiteralValue for type 'DNS': %1", literalValue).toString());
        }
    } else if(literalType == "RID") {
        ValueCheck check = initOIDCheck();
        if(!check.isValid(literalValue)) {
            LOGIT_DEBUG("Wrong LiteralValue for type 'RID': " << literalValue);
            result.append(Format("Wrong LiteralValue for type 'RID': %1", literalValue).toString());
        }
    } else if(literalType == "IP") {
        ValueCheck check = initIPCheck();
        if(!check.isValid(literalValue)) {
            LOGIT_DEBUG("Wrong LiteralValue for type 'IP': " << literalValue);
            result.append(Format("Wrong LiteralValue for type 'IP': %1", literalValue).toString());
        }
    } else {
        LOGIT_DEBUG("Unknown Type in LiteralValue: " << literalType);
        result.append(Format("Unknown Type in LiteralValue: %1", literalType).toString());
    }
    return result;
}

blocxx::String
LiteralValue::toString() const
{
    return (literalType + ":" + literalValue);
}

blocxx::StringArray
LiteralValue::dump() const
{
    StringArray result;
    result.append("LiteralValue::dump()");

    result.append(literalType + ":" + literalValue);

    return result;
}
