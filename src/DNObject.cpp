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

  File:       DNObject.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/DNObject.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

RDNObject::RDNObject()
    : type(String()), value(String())
{
}

RDNObject::RDNObject(const String& type, const String& value)
    : type(type), value(value)
{
    StringArray r = this->verify();
    if(!r.empty()) {
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

RDNObject::RDNObject(const RDNObject& rdn)
    : type(rdn.type), value(rdn.value)
{
}

RDNObject::~RDNObject()
{}

RDNObject&
RDNObject::operator=(const RDNObject& rdn)
{
    if(this == &rdn) return *this;
    
    type  = rdn.type;
    value = rdn.value;

    return *this;
}

void
RDNObject::setRDN(const String& type, const String& value)
{
    String oldType  = this->type;
    String oldValue = this->value;

    this->type  = type;
    this->value = value;

    StringArray r = this->verify();
    if(!r.empty()) {
        this->type  = oldType;
        this->value = oldValue;
        
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }    
}


blocxx::String
RDNObject::getType() const
{
    return type;
}

blocxx::String
RDNObject::getValue() const
{
    return value;
}

bool
RDNObject::valid() const
{
    if(type.empty()) {
        LOGIT_DEBUG("type is empty");
        return false;
    }
    if(value.empty()) {
        LOGIT_DEBUG("value is empty");
        return false;
    }
    // FIXME: define and check pre defined types ?

    return true;
}

blocxx::StringArray
RDNObject::verify() const
{
    StringArray result;

    if(type.empty()) {
        result.append("type is empty");
    }
    if(value.empty()) {
        result.append("value is empty");
    }
    // FIXME: define and check pre defined types ?

    LOGIT_DEBUG_STRINGARRAY("RDNObject::verify()", result);

    return result;
}


// ######################################################################

DNObject::DNObject()
    : dn(blocxx::List<RDNObject>())
{
}

DNObject::DNObject(const blocxx::List<RDNObject> &dn)
    : dn(dn)
{
    StringArray r = this->verify();
    if(!r.empty()) {
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
}

DNObject::DNObject(const DNObject& dn)
    : dn(dn.dn)
{}

DNObject::~DNObject()
{}

DNObject&
DNObject::operator=(const DNObject& dn)
{
    if(this == &dn) return *this;
    
    this->dn = dn.dn;
    
    return *this;
}

void
DNObject::setDN(const blocxx::List<RDNObject> &dn)
{
    blocxx::List<RDNObject> oldDN = this->dn;
    
    this->dn = dn;

    StringArray r = this->verify();
    if(!r.empty()) {
        this->dn = oldDN;
        
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }    
}

blocxx::List<RDNObject>
DNObject::getDN() const
{
    return dn;
}

bool
DNObject::valid() const
{
    if(dn.empty()) {
        LOGIT_DEBUG("empty DN");
        return false;
    }
    blocxx::List<RDNObject>::const_iterator it = dn.begin();
    for(; it != dn.end(); ++it) {
        if(!(*it).valid()) {
            return false;
        }
    }
    return true;
}

blocxx::StringArray
DNObject::verify() const
{
    StringArray result;

    if(dn.empty()) {
        result.append("empty DN");
    }
    blocxx::List<RDNObject>::const_iterator it = dn.begin();
    for(; it != dn.end(); ++it) {
        result.appendArray((*it).verify());
    }
    LOGIT_DEBUG_STRINGARRAY("DNObject::verify()", result);

    return result;
}
