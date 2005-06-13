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

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

RDNObject::RDNObject()
{
}

RDNObject::RDNObject(const String& type, const String& value)
{
}

RDNObject::RDNObject(const RDNObject& rdn)
{
}

RDNObject::~RDNObject()
{
}

RDNObject&
RDNObject::operator=(const RDNObject& rdn)
{
    return *this;
}

void
RDNObject::setType(const String& type)
{
    this->type = type;
}

void
RDNObject::setValue(const String& value)
{
    this->value = value;
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


// ######################################################################

DNObject::DNObject()
{
}

DNObject::DNObject(const blocxx::List<RDNObject> &dn)
{
}

DNObject::DNObject(const DNObject& dn)
{
}

DNObject::~DNObject()
{
}

DNObject&
DNObject::operator=(const DNObject& dn)
{
    return *this;
}

void
DNObject::setDN(const blocxx::List<RDNObject> &dn)
{
    this->dn = dn;
}

blocxx::List<RDNObject>
DNObject::getDN() const
{
    return dn;
}


