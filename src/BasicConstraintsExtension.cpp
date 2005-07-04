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

  File:       BasicConstraintsExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/BasicConstraintsExtension.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

BasicConstraintsExtension::BasicConstraintsExtension()
    : ExtensionBase(), ca(false), pathlen(-1)
{}

BasicConstraintsExtension::BasicConstraintsExtension(CA& ca, Type type)
    : ExtensionBase(), ca(false), pathlen(-1)
{}

BasicConstraintsExtension::BasicConstraintsExtension(bool isCa, blocxx::Int32 pathLength)
    : ExtensionBase(), ca(isCa), pathlen(pathLength)
{
    setPresent(true);
}

BasicConstraintsExtension::BasicConstraintsExtension(const BasicConstraintsExtension& extension)
    : ExtensionBase(extension), ca(extension.ca), pathlen(extension.pathlen)
{}

BasicConstraintsExtension::~BasicConstraintsExtension()
{}


BasicConstraintsExtension&
BasicConstraintsExtension::operator=(const BasicConstraintsExtension& extension)
{
    if(this == &extension) return *this;

    ExtensionBase::operator=(extension);
    ca      = extension.ca;
    pathlen = extension.pathlen;

    return *this;
}

void
BasicConstraintsExtension::setBasicConstraints(bool isCa, blocxx::Int32 pathLength)
{
    ca = isCa;
    pathlen = pathLength;
    setPresent(true);
}

bool
BasicConstraintsExtension::isCA() const
{
    if(!isPresent()) {
        LOGIT_ERROR("BasicConstraintsExtension is not present");
        BLOCXX_THROW(limal::RuntimeException, "BasicConstraintsExtension is not present");
    }
    return ca;
}

blocxx::Int32
BasicConstraintsExtension::getPathLength() const
{
    if(!isPresent()) {
        LOGIT_ERROR("BasicConstraintsExtension is not present");
        BLOCXX_THROW(limal::RuntimeException, "BasicConstraintsExtension is not present");
    }
    return pathlen;
}

void
BasicConstraintsExtension::commit2Config(CA& ca, Type type)
{
}

bool
BasicConstraintsExtension::valid() const
{
    if(!isPresent()) {
        LOGIT_DEBUG("return BasicConstraintsExtension::valid() is true");
        return true;
    }

    if(ca && pathlen < -1) {
        LOGIT_DEBUG("return BasicConstraintsExtension::valid() is false");
        return false;
    }
    if(!ca && pathlen != -1) {
        LOGIT_DEBUG("return BasicConstraintsExtension::valid() is false");
        return false;
    }
    LOGIT_DEBUG("return BasicConstraintsExtension::valid() is true");
    return true;
}

blocxx::StringArray
BasicConstraintsExtension::verify() const
{
    blocxx::StringArray result;

    if(!isPresent()) return result;
    
    if(ca && pathlen < -1) {
        result.append(Format("invalid value for pathLength(%1). Has to be >= -1", pathlen).toString());
    }
    if(!ca && pathlen != -1) {
        result.append(Format("invalid value for pathLength(%1). Has to be -1", pathlen).toString());
    }
    LOGIT_DEBUG_STRINGARRAY("BasicConstraintsExtension::verify()", result);
    return result;
}
