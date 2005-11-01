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

  File:       ExtendedKeyUsageExt.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  <limal/ca-mgm/BitExtensions.hpp>
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

#include "Utils.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;

ExtendedKeyUsageExt::ExtendedKeyUsageExt()
    : ExtensionBase(), usage(StringList())
{}

ExtendedKeyUsageExt::ExtendedKeyUsageExt(CAConfig* caConfig, Type type)
    : ExtensionBase(), usage(StringList())
{
    LOGIT_DEBUG("Parse ExtendedKeyUsage");

    // These types are not supported by this object
    if(type == E_CRL)
    {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1",
                                                   type).c_str());
    }

    bool p = caConfig->exists(type2Section(type, true), "extendedKeyUsage");
    if(p)
    {
        String      ct    = caConfig->getValue(type2Section(type, true),
                                               "extendedKeyUsage");
        StringArray sp    = PerlRegEx("\\s*,\\s*").split(ct);

        StringArray::const_iterator it = sp.begin();
        if(sp[0].equalsIgnoreCase("critical"))
        {
            setCritical(true);
            ++it;             // ignore critical for further checks
        }

        for(; it != sp.end(); ++it)
        {
            if(checkValue(*it))
            {
                usage.push_back(*it);
            }
            else
                LOGIT_INFO("Unknown ExtendedKeyUsage option: " << (*it));
        }
    }
    setPresent(p);
}

ExtendedKeyUsageExt::ExtendedKeyUsageExt(const StringList& extKeyUsages)
    : ExtensionBase()
{
    StringList::const_iterator it = extKeyUsages.begin();
    for(; it != extKeyUsages.end(); ++it)
    {
        if(checkValue(*it))
        {
            usage.push_back(*it);
        }
        else
        {
            LOGIT_INFO("Unknown ExtendedKeyUsage option: " << (*it));
            BLOCXX_THROW(limal::ValueException,
                         Format("invalid ExtendedKeyUsage option: %1",
                                *it).c_str());
        }
    }
    
    if(usage.empty())
    {
        BLOCXX_THROW(limal::ValueException, "invalid ExtendedKeyUsageExt.");
    }
    
    setPresent(true);
}


ExtendedKeyUsageExt::ExtendedKeyUsageExt(const ExtendedKeyUsageExt& extension)
    : ExtensionBase(extension), usage(extension.usage)
{}

ExtendedKeyUsageExt::~ExtendedKeyUsageExt()
{}


ExtendedKeyUsageExt&
ExtendedKeyUsageExt::operator=(const ExtendedKeyUsageExt& extension)
{
    if(this == &extension) return *this;

    ExtensionBase::operator=(extension);
    usage = extension.usage;

    return *this;
}

void
ExtendedKeyUsageExt::setExtendedKeyUsage(const StringList& usageList)
{
    StringList::const_iterator it = usageList.begin();
    for(; it != usageList.end(); ++it)
    {
        if(checkValue(*it))
        {
            usage.push_back(*it);
        }
        else
        {
            LOGIT_INFO("Unknown ExtendedKeyUsage option: " << (*it));
            BLOCXX_THROW(limal::ValueException,
                         Format("invalid ExtendedKeyUsage option: %1",
                                *it).c_str());
        }
    }

    if(usage.empty())
    {
        BLOCXX_THROW(limal::ValueException, "invalid ExtendedKeyUsageExt.");
    }

    setPresent(true);
}


StringList
ExtendedKeyUsageExt::getExtendedKeyUsage() const
{
    if(!isPresent())
    {
        BLOCXX_THROW(limal::RuntimeException,
                     "ExtendedKeyUsageExt is not present");
    }
    return usage;
}
        
bool
ExtendedKeyUsageExt::isEnabledFor(const String& extKeyUsage) const
{
    // if ! isPresent() ... throw exceptions?
    if(!isPresent() || usage.empty()) return false;

    StringList::const_iterator it = usage.begin();
    for(;it != usage.end(); ++it)
    {
        if(extKeyUsage.equalsIgnoreCase(*it))
        {
            return true;
        }
    }    
    return false;
}
  
void
ExtendedKeyUsageExt::commit2Config(CA& ca, Type type) const
{
    if(!valid())
    {
        LOGIT_ERROR("invalid ExtendedKeyUsageExt object");
        BLOCXX_THROW(limal::ValueException, "invalid ExtendedKeyUsageExt object");
    }

    // This extension is not supported by type CRL
    if(type == E_CRL)
    {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent())
    {
        String extendedKeyUsageString;

        if(isCritical()) extendedKeyUsageString += "critical,";

        StringList::const_iterator it = usage.begin();
        for(; it != usage.end(); ++it)
        {
            extendedKeyUsageString += (*it)+",";
        }

        ca.getConfig()->setValue(type2Section(type, true),
                                 "extendedKeyUsage", 
                                 extendedKeyUsageString.erase(extendedKeyUsageString.length()-1));
    }
    else
    {
        ca.getConfig()->deleteValue(type2Section(type, true), "extendedKeyUsage");
    }
}

bool
ExtendedKeyUsageExt::valid() const
{
    if(!isPresent()) return true;

    if(usage.empty())
    {
        return false;
    }

    StringList::const_iterator it = usage.begin();
    for(;it != usage.end(); it++)
    {
        if(!checkValue(*it))
        {
            return false;
        }
    }
    return true;
}

blocxx::StringArray
ExtendedKeyUsageExt::verify() const
{
    blocxx::StringArray result;

    if(!isPresent()) return result;

    if(usage.empty())
    {
        result.append(String("invalid ExtendedKeyUsageExt."));
    }

    StringList::const_iterator it = usage.begin();
    for(;it != usage.end(); it++)
    {
        if(!checkValue(*it))
        {
            result.append(Format("invalid additionalOID(%1)", *it).toString());
        }
    }
    LOGIT_DEBUG_STRINGARRAY("ExtendedKeyUsageExt::verify()", result);
    return result;
}

blocxx::StringArray
ExtendedKeyUsageExt::dump() const
{
    StringArray result;
    result.append("ExtendedKeyUsageExt::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    StringList::const_iterator it = usage.begin();
    for(; it != usage.end(); ++it)
    {
        result.append("Extended KeyUsage = " + (*it));
    }

    return result;
}

bool
ExtendedKeyUsageExt::checkValue(const String& value) const
{
    StringList validValues;
    validValues.push_back("serverAuth");
    validValues.push_back("clientAuth");
    validValues.push_back("codeSigning");
    validValues.push_back("emailProtection");
    validValues.push_back("timeStamping");
    validValues.push_back("msCodeInd");
    validValues.push_back("msCodeCom");
    validValues.push_back("msCTLSign");
    validValues.push_back("msSGC");
    validValues.push_back("msEFS");
    validValues.push_back("nsSGC");
    
    StringList::const_iterator it = validValues.begin();
    for(; it != validValues.end(); ++it)
    {
        if(value.equalsIgnoreCase(*it))
        {
            return true;
        }
    }
    
    return initOIDCheck().isValid(value);
}
    
}
}
