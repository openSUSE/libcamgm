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

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
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

blocxx::StringArray
AuthorityKeyIdentifierExtension::dump() const
{
    StringArray result;
    result.append("AuthorityKeyIdentifierExtension::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    result.append("KeyID = " + keyid);
    result.append("DirName = " + DirName);
    result.append("serial = " + serial);

    return result;
}
        
// protected

AuthorityKeyIdentifierExtension::AuthorityKeyIdentifierExtension()
    : ExtensionBase()
{}


// private
void 
AuthorityKeyIdentifierExtension::commit2Config(CA&, Type) const
{}

}
}
