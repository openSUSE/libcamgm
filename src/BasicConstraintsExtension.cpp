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
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

#include  "Utils.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;

BasicConstraintsExt::BasicConstraintsExt()
    : ExtensionBase(), ca(false), pathlen(-1)
{}

BasicConstraintsExt::BasicConstraintsExt(CAConfig* caConfig, Type type)
    : ExtensionBase(), ca(false), pathlen(-1)
{
    // These types are not supported by this object
    if(type == E_CRL)
    {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = caConfig->exists(type2Section(type, true), "basicConstraints");
    if(p) {
        bool          isCA = false;
        blocxx::Int32 pl   = -1;

        StringArray   sp   = PerlRegEx("\\s*,\\s*")
            .split(caConfig->getValue(type2Section(type, true), "basicConstraints"));
        if(sp[0].equalsIgnoreCase("critical"))  setCritical(true); 

        StringArray::const_iterator it = sp.begin();
        for(; it != sp.end(); ++it) {
            if((*it).equalsIgnoreCase("ca:true"))  isCA = true; 
            else if((*it).equalsIgnoreCase("ca:false"))  isCA = false;
            else if((*it).startsWith("pathlen:", String::E_CASE_INSENSITIVE)) {
                StringArray plA = PerlRegEx(":").split(*it);
                pl = plA[1].toInt32();
            }
        }
        setBasicConstraints(isCA, pl);
    }
    setPresent(p);
}

BasicConstraintsExt::BasicConstraintsExt(bool isCa, blocxx::Int32 pathLength)
    : ExtensionBase(), ca(isCa), pathlen(pathLength)
{
    setPresent(true);
}

BasicConstraintsExt::BasicConstraintsExt(const BasicConstraintsExt& extension)
    : ExtensionBase(extension), ca(extension.ca), pathlen(extension.pathlen)
{}

BasicConstraintsExt::~BasicConstraintsExt()
{}


BasicConstraintsExt&
BasicConstraintsExt::operator=(const BasicConstraintsExt& extension)
{
    if(this == &extension) return *this;

    ExtensionBase::operator=(extension);
    ca      = extension.ca;
    pathlen = extension.pathlen;

    return *this;
}

void
BasicConstraintsExt::setBasicConstraints(bool isCa, blocxx::Int32 pathLength)
{
    ca = isCa;
    pathlen = pathLength;
    setPresent(true);
}

bool
BasicConstraintsExt::isCA() const
{
    if(!isPresent()) {
        LOGIT_ERROR("BasicConstraintsExt is not present");
        BLOCXX_THROW(limal::RuntimeException, "BasicConstraintsExt is not present");
    }
    return ca;
}

blocxx::Int32
BasicConstraintsExt::getPathLength() const
{
    if(!isPresent()) {
        LOGIT_ERROR("BasicConstraintsExt is not present");
        BLOCXX_THROW(limal::RuntimeException, "BasicConstraintsExt is not present");
    }
    return pathlen;
}

void
BasicConstraintsExt::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid BasicConstraintsExt object");
        BLOCXX_THROW(limal::ValueException, "invalid BasicConstraintsExt object");
    }

    // This extension is not supported by type CRL
    if(type == E_CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent()) {
        String basicConstraintsString;

        if(isCritical()) basicConstraintsString += "critical,";

        if(this->ca) {
            basicConstraintsString += "CA:TRUE";
            if(pathlen > -1) {
                basicConstraintsString += ",pathlen:"+String(pathlen);
            }
        } else {
            basicConstraintsString += "CA:FALSE";
        }
        ca.getConfig()->setValue(type2Section(type, true), "basicConstraints", basicConstraintsString);
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "basicConstraints");
    }
}

bool
BasicConstraintsExt::valid() const
{
    if(!isPresent()) {
        LOGIT_DEBUG("return BasicConstraintsExt::valid() is true");
        return true;
    }

    if(ca && pathlen < -1) {
        LOGIT_DEBUG("return BasicConstraintsExt::valid() is false");
        return false;
    }
    if(!ca && pathlen != -1) {
        LOGIT_DEBUG("return BasicConstraintsExt::valid() is false");
        return false;
    }
    LOGIT_DEBUG("return BasicConstraintsExt::valid() is true");
    return true;
}

blocxx::StringArray
BasicConstraintsExt::verify() const
{
    blocxx::StringArray result;

    if(!isPresent()) return result;
    
    if(ca && pathlen < -1) {
        result.append(Format("invalid value for pathLength(%1). Has to be >= -1", pathlen).toString());
    }
    if(!ca && pathlen != -1) {
        result.append(Format("invalid value for pathLength(%1). Has to be -1", pathlen).toString());
    }
    LOGIT_DEBUG_STRINGARRAY("BasicConstraintsExt::verify()", result);
    return result;
}

blocxx::StringArray
BasicConstraintsExt::dump() const
{
    StringArray result;
    result.append("BasicConstraintsExt::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    result.append("CA = " + Bool(ca).toString());
    result.append("pathlen = " + String(pathlen));

    return result;
}

}
}
