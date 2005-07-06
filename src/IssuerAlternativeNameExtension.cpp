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

  File:       IssuerAlternativeNameExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/IssuerAlternativeNameExtension.hpp>
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/Exception.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;


IssuerAlternativeNameExtension::IssuerAlternativeNameExtension()
    :ExtensionBase(), issuerCopy(false), altNameList(blocxx::List<LiteralValue>())
{}

IssuerAlternativeNameExtension::IssuerAlternativeNameExtension(bool copyIssuer, 
                                                               const blocxx::List<LiteralValue> &alternativeNameList)
    :ExtensionBase(), issuerCopy(copyIssuer), altNameList(alternativeNameList)
{
    StringArray r = checkLiteralValueList(alternativeNameList);
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    setPresent(true);
}

IssuerAlternativeNameExtension::IssuerAlternativeNameExtension(CA& ca, Type type)
    :ExtensionBase(), issuerCopy(false), altNameList(blocxx::List<LiteralValue>())
{
    // These types are not supported by this object
    if(type == Client_Req || type == Server_Req || type == CA_Req) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = ca.getConfig()->exists(type2Section(type, true), "issuerAltName");
    if(p) {
        StringArray   sp   = PerlRegEx("\\s*,\\s*")
            .split(ca.getConfig()->getValue(type2Section(type, true), "issuerAltName"));
        if(sp[0].equalsIgnoreCase("critical"))  setCritical(true);

        StringArray::const_iterator it = sp.begin();
        for(; it != sp.end(); ++it) {
            if((*it).indexOf(":") != String::npos) {
                if((*it).equalsIgnoreCase("issuer:copy"))  
                    issuerCopy = true;
                else {

                    try {
                        
                        LiteralValue lv = LiteralValue(*it);
                        altNameList.push_back(lv);
                    
                    } catch(blocxx::Exception& e) {
                        LOGIT_ERROR("invalid value: " << *it);
                    }
                }
            }
        }
    }
    setPresent(p);
}

IssuerAlternativeNameExtension::IssuerAlternativeNameExtension(const IssuerAlternativeNameExtension& extension)
    :ExtensionBase(), issuerCopy(extension.issuerCopy),
     altNameList(extension.altNameList)
{}

IssuerAlternativeNameExtension::~IssuerAlternativeNameExtension()
{}

IssuerAlternativeNameExtension&
IssuerAlternativeNameExtension::operator=(const IssuerAlternativeNameExtension& extension)
{
    if(this == &extension) return *this;
    
    ExtensionBase::operator=(extension);
    issuerCopy = extension.issuerCopy;
    altNameList = extension.altNameList;

    return *this;
}

void
IssuerAlternativeNameExtension::setCopyIssuer(bool copyIssuer)
{
    issuerCopy = copyIssuer;
    setPresent(true);
}

bool
IssuerAlternativeNameExtension::getCopyIssuer() const
{
    if(!isPresent()) {
        LOGIT_ERROR("IssuerAlternativeNameExtension is not present");
        BLOCXX_THROW(limal::RuntimeException, "IssuerAlternativeNameExtension is not present");
    }
    return issuerCopy;
}

void
IssuerAlternativeNameExtension::setAlternativeNameList(const blocxx::List<LiteralValue> &alternativeNameList)
{
    StringArray r = checkLiteralValueList(alternativeNameList);
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    altNameList = alternativeNameList;
    setPresent(true);
}

blocxx::List<LiteralValue>
IssuerAlternativeNameExtension::getAlternativeNameList() const
{
    if(!isPresent()) {
        LOGIT_ERROR("IssuerAlternativeNameExtension is not present");
        BLOCXX_THROW(limal::RuntimeException, "IssuerAlternativeNameExtension is not present");
    }
    return altNameList;
}

void
IssuerAlternativeNameExtension::addIssuerAltName(const LiteralValue& altName)
{
    if(!altName.valid()) {
        LOGIT_ERROR("invalid literal value for IssuerAlternativeNameExtension");
        BLOCXX_THROW(limal::ValueException, 
                     "invalid literal value for IssuerAlternativeNameExtension");
    }
    altNameList.push_back(altName);
    setPresent(true);
}


void
IssuerAlternativeNameExtension::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid IssuerAlternativeNameExtension object");
        BLOCXX_THROW(limal::ValueException, "invalid IssuerAlternativeNameExtension object");
    }

    // These types are not supported by this object
    if(type == Client_Req || type == Server_Req || type == CA_Req) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent()) {
        String extString;

        if(isCritical()) extString += "critical,";

        if(issuerCopy) extString += "issuer:copy,";

        blocxx::List<LiteralValue>::const_iterator it = altNameList.begin();
        for(;it != altNameList.end(); ++it) {
            extString += (*it).toString()+",";
        }

        ca.getConfig()->setValue(type2Section(type, true), "issuerAltName",
                                 extString.erase(extString.length()-2));
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "issuerAltName");
    }
}

bool
IssuerAlternativeNameExtension::valid() const
{
    if(!isPresent()) {
        LOGIT_DEBUG("return IssuerAlternativeNameExtension::valid() ist true");
        return true;
    }

    if(!issuerCopy && altNameList.empty()) {
        LOGIT_DEBUG("return IssuerAlternativeNameExtension::valid() ist false");
        return false;
    }
    StringArray r = checkLiteralValueList(altNameList);
    if(!r.empty()) {
        LOGIT_DEBUG(r[0]);
        return false;
    }
    LOGIT_DEBUG("return IssuerAlternativeNameExtension::valid() ist true");
    return true;
}

blocxx::StringArray
IssuerAlternativeNameExtension::verify() const
{
    blocxx::StringArray result;

    if(!isPresent()) return result;

    if(!issuerCopy && altNameList.empty()) {
        result.append(String("invalid value for IssuerAlternativeNameExtension"));
    }
    result.appendArray(checkLiteralValueList(altNameList));

    LOGIT_DEBUG_STRINGARRAY("IssuerAlternativeNameExtension::verify()", result);

    return result;
}
