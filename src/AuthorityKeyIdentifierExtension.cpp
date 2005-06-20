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
#include  <limal/Exception.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

AuthorityKeyIdentifierExtension::AuthorityKeyIdentifierExtension(const AuthorityKeyIdentifierExtension& extension)
    : ExtensionBase(extension),
      keyid(extension.keyid),
      DirName(extension.DirName),
      serial(extension.serial)
{}

AuthorityKeyIdentifierExtension::~AuthorityKeyIdentifierExtension()
{}

AuthorityKeyIdentifierExtension& 
AuthorityKeyIdentifierExtension::operator=(const AuthorityKeyIdentifierExtension& extension)
{
    if(this == &extension) return *this;

    ExtensionBase::operator=(extension);
    keyid = extension.keyid;
    DirName = extension.DirName;
    serial = extension.serial;
   
    return *this;
}

blocxx::String         
AuthorityKeyIdentifierExtension::getKeyID() const
{
    if(!isPresent()) {
        LOGIT_ERROR("AuthorityKeyIdentifierExtension is not present");
        BLOCXX_THROW(limal::RuntimeException, "AuthorityKeyIdentifierExtension is not present");
    }
    return keyid;
}

blocxx::String         
AuthorityKeyIdentifierExtension::getDirName() const
{
    if(!isPresent()) {
        LOGIT_ERROR("AuthorityKeyIdentifierExtension is not present");
        BLOCXX_THROW(limal::RuntimeException, "AuthorityKeyIdentifierExtension is not present");
    }
    return DirName;
}

blocxx::String         
AuthorityKeyIdentifierExtension::getSerial() const
{
    if(!isPresent()) {
        LOGIT_ERROR("AuthorityKeyIdentifierExtension is not present");
        BLOCXX_THROW(limal::RuntimeException, "AuthorityKeyIdentifierExtension is not present");
    }
    return serial;
}

bool
AuthorityKeyIdentifierExtension::valid() const
{
    return true;
}

blocxx::StringArray
AuthorityKeyIdentifierExtension::verify() const
{
    return blocxx::StringArray();
}

        
// protected

AuthorityKeyIdentifierExtension::AuthorityKeyIdentifierExtension()
    : ExtensionBase()
{}


// private
void 
AuthorityKeyIdentifierExtension::commit2Config(CA& ca, Type type)
{}
