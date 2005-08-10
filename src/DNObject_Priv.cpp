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

  File:       DNObject_Priv.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  "DNObject_Priv.hpp"
#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

RDNObject_Priv::RDNObject_Priv()
    : RDNObject()
{
}

RDNObject_Priv::RDNObject_Priv(const String& type, const String& value,
                               const String&  prompt,
                               blocxx::UInt32 min,
                               blocxx::UInt32 max)
    : RDNObject()
{
    this->type   = type;
    this->value  = value;
    this->prompt = prompt;
    this->min    = min;
    this->max    = max;
}

RDNObject_Priv::~RDNObject_Priv()
{}

void
RDNObject_Priv::setRDN(const String& type, const String& value,
                       const String&  prompt,
                       blocxx::UInt32 min,
                       blocxx::UInt32 max)
{
    this->type   = type;
    this->value  = value;
    this->prompt = prompt;
    this->min    = min;
    this->max    = max;
}


// ##############################################################

DNObject_Priv::DNObject_Priv(X509* cert)
    : DNObject()
{
}

DNObject_Priv::~DNObject_Priv()
{
}

//  private:
DNObject_Priv::DNObject_Priv(const DNObject_Priv& obj)
    : DNObject(obj)
{
}

DNObject_Priv&
DNObject_Priv::operator=(const DNObject_Priv& obj)
{
    if(this == &obj) return *this;
    
    DNObject::operator=(obj);

    return *this;
}
