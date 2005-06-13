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

  File:       AuthorityInfoAccessExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/AuthorityInfoAccessExtension.hpp>

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;


AuthorityInfoAccessExtension::AuthorityInfoAccessExtension()
    : ExtensionBase()
{}

AuthorityInfoAccessExtension::AuthorityInfoAccessExtension(const AuthorityInfoAccessExtension& extension)
    : ExtensionBase(extension), type(extension.type), accessIOD(extension.accessIOD), 
      locList(extension.locList)
{}

AuthorityInfoAccessExtension::AuthorityInfoAccessExtension(CA& ca, Type type)
    : ExtensionBase()
{
    //Parse the config file
}

AuthorityInfoAccessExtension::~AuthorityInfoAccessExtension() {}

AuthorityInfoAccessExtension& 
AuthorityInfoAccessExtension::operator=(const AuthorityInfoAccessExtension& extension)
{
    return *this;
}
        
void
AuthorityInfoAccessExtension::setAccessOIDType(AccessOIDType type, String oid)
{
    setPresent(true);
}

AuthorityInfoAccessExtension::AccessOIDType
AuthorityInfoAccessExtension::getAccessOIDType() const
{
    if(!isPresent()) {
        return none;
    }

    return none;
}

blocxx::String                 
AuthorityInfoAccessExtension::getAccessOID() const
{
    if(!isPresent()) {
        return String();
    }
    return String();
}

void                   
AuthorityInfoAccessExtension::setLocation(List<LiteralValueBase> locationList)
{
    setPresent(true);

}

List<LiteralValueBase> 
AuthorityInfoAccessExtension::getLocation() const
{
    if(!isPresent()) {
        return List<LiteralValueBase>();
    }
    return List<LiteralValueBase>();
}

void                   
AuthorityInfoAccessExtension::addLocation(const LiteralValueBase& location)
{
    setPresent(true);

}

void 
AuthorityInfoAccessExtension::commit2Config(CA& ca, Type type)
{
    if(!isPresent()) {
        return;
    }

}

