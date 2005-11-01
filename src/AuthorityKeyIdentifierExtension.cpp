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

AuthorityKeyIdentifierExt::AuthorityKeyIdentifierExt(const AuthorityKeyIdentifierExt& extension)
    : ExtensionBase(extension),
      keyid(extension.keyid),
      DirName(extension.DirName),
      serial(extension.serial)
{}

AuthorityKeyIdentifierExt::~AuthorityKeyIdentifierExt()
{}

AuthorityKeyIdentifierExt& 
AuthorityKeyIdentifierExt::operator=(const AuthorityKeyIdentifierExt& extension)
{
    if(this == &extension) return *this;

    ExtensionBase::operator=(extension);
    keyid = extension.keyid;
    DirName = extension.DirName;
    serial = extension.serial;
   
    return *this;
}

blocxx::String         
AuthorityKeyIdentifierExt::getKeyID() const
{
    if(!isPresent()) {
        LOGIT_ERROR("AuthorityKeyIdentifierExt is not present");
        BLOCXX_THROW(limal::RuntimeException, "AuthorityKeyIdentifierExt is not present");
    }
    return keyid;
}

blocxx::String         
AuthorityKeyIdentifierExt::getDirName() const
{
    if(!isPresent()) {
        LOGIT_ERROR("AuthorityKeyIdentifierExt is not present");
        BLOCXX_THROW(limal::RuntimeException, "AuthorityKeyIdentifierExt is not present");
    }
    return DirName;
}

blocxx::String         
AuthorityKeyIdentifierExt::getSerial() const
{
    if(!isPresent()) {
        LOGIT_ERROR("AuthorityKeyIdentifierExt is not present");
        BLOCXX_THROW(limal::RuntimeException, "AuthorityKeyIdentifierExt is not present");
    }
    return serial;
}

bool
AuthorityKeyIdentifierExt::valid() const
{
    return true;
}

blocxx::StringArray
AuthorityKeyIdentifierExt::verify() const
{
    return blocxx::StringArray();
}

blocxx::StringArray
AuthorityKeyIdentifierExt::dump() const
{
    StringArray result;
    result.append("AuthorityKeyIdentifierExt::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    result.append("KeyID = " + keyid);
    result.append("DirName = " + DirName);
    result.append("serial = " + serial);

    return result;
}
        
// protected

AuthorityKeyIdentifierExt::AuthorityKeyIdentifierExt()
    : ExtensionBase()
{}


// private
void 
AuthorityKeyIdentifierExt::commit2Config(CA&, Type) const
{}

}
}
