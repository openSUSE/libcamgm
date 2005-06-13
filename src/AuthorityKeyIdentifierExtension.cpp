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

  File:       AuthorityKeyIdentifierExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  <limal/ca-mgm/AuthorityKeyIdentifierExtension.hpp>

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

AuthorityKeyIdentifierExtension::AuthorityKeyIdentifierExtension(const AuthorityKeyIdentifierExtension& extension)
    : ExtensionBase()
{

}

AuthorityKeyIdentifierExtension::~AuthorityKeyIdentifierExtension()
{}

AuthorityKeyIdentifierExtension& 
AuthorityKeyIdentifierExtension::operator=(const AuthorityKeyIdentifierExtension& extension)
{
    return *this;
}

blocxx::String         
AuthorityKeyIdentifierExtension::getKeyID() const
{
    return keyid;
}

blocxx::String         
AuthorityKeyIdentifierExtension::getDirName() const
{
    return DirName;
}

blocxx::String         
AuthorityKeyIdentifierExtension::getSerial() const
{
    return serial;
}
        
// protected

AuthorityKeyIdentifierExtension::AuthorityKeyIdentifierExtension()
    : ExtensionBase()
{}


// private
void 
AuthorityKeyIdentifierExtension::commit2Config(CA& ca, Type type)
{}
