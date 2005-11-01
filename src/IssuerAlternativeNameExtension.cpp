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

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;


IssuerAlternativeNameExt::IssuerAlternativeNameExt()
    :ExtensionBase(), issuerCopy(false), altNameList(blocxx::List<LiteralValue>())
{}

IssuerAlternativeNameExt::IssuerAlternativeNameExt(bool copyIssuer, 
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

IssuerAlternativeNameExt::IssuerAlternativeNameExt(CAConfig* caConfig, Type type)
    :ExtensionBase(), issuerCopy(false), altNameList(blocxx::List<LiteralValue>())
{
    // These types are not supported by this object
    if(type == E_Client_Req || type == E_Server_Req || type == E_CA_Req)
    {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = caConfig->exists(type2Section(type, true), "issuerAltName");
    if(p) {
        StringArray   sp   = PerlRegEx("\\s*,\\s*")
            .split(caConfig->getValue(type2Section(type, true), "issuerAltName"));
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

IssuerAlternativeNameExt::IssuerAlternativeNameExt(const IssuerAlternativeNameExt& extension)
    :ExtensionBase(extension), issuerCopy(extension.issuerCopy),
     altNameList(extension.altNameList)
{}

IssuerAlternativeNameExt::~IssuerAlternativeNameExt()
{}

IssuerAlternativeNameExt&
IssuerAlternativeNameExt::operator=(const IssuerAlternativeNameExt& extension)
{
    if(this == &extension) return *this;
    
    ExtensionBase::operator=(extension);
    issuerCopy = extension.issuerCopy;
    altNameList = extension.altNameList;

    return *this;
}

void
IssuerAlternativeNameExt::setCopyIssuer(bool copyIssuer)
{
    issuerCopy = copyIssuer;
    setPresent(true);
}

bool
IssuerAlternativeNameExt::getCopyIssuer() const
{
    if(!isPresent()) {
        LOGIT_ERROR("IssuerAlternativeNameExt is not present");
        BLOCXX_THROW(limal::RuntimeException, "IssuerAlternativeNameExt is not present");
    }
    return issuerCopy;
}

void
IssuerAlternativeNameExt::setAlternativeNameList(const blocxx::List<LiteralValue> &alternativeNameList)
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
IssuerAlternativeNameExt::getAlternativeNameList() const
{
    if(!isPresent()) {
        LOGIT_ERROR("IssuerAlternativeNameExt is not present");
        BLOCXX_THROW(limal::RuntimeException, "IssuerAlternativeNameExt is not present");
    }
    return altNameList;
}

void
IssuerAlternativeNameExt::addIssuerAltName(const LiteralValue& altName)
{
    if(!altName.valid()) {
        LOGIT_ERROR("invalid literal value for IssuerAlternativeNameExt");
        BLOCXX_THROW(limal::ValueException, 
                     "invalid literal value for IssuerAlternativeNameExt");
    }
    altNameList.push_back(altName);
    setPresent(true);
}


void
IssuerAlternativeNameExt::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid IssuerAlternativeNameExt object");
        BLOCXX_THROW(limal::ValueException, "invalid IssuerAlternativeNameExt object");
    }

    // These types are not supported by this object
    if(type == E_Client_Req || type == E_Server_Req || type == E_CA_Req) {
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
                                 extString.erase(extString.length()-1));
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "issuerAltName");
    }
}

bool
IssuerAlternativeNameExt::valid() const
{
    if(!isPresent()) {
        LOGIT_DEBUG("return IssuerAlternativeNameExt::valid() is true");
        return true;
    }

    if(!issuerCopy && altNameList.empty()) {
        LOGIT_DEBUG("return IssuerAlternativeNameExt::valid() is false");
        return false;
    }
    StringArray r = checkLiteralValueList(altNameList);
    if(!r.empty()) {
        LOGIT_DEBUG(r[0]);
        return false;
    }
    LOGIT_DEBUG("return IssuerAlternativeNameExt::valid() is true");
    return true;
}

blocxx::StringArray
IssuerAlternativeNameExt::verify() const
{
    blocxx::StringArray result;

    if(!isPresent()) return result;

    if(!issuerCopy && altNameList.empty()) {
        result.append(String("invalid value for IssuerAlternativeNameExt"));
    }
    result.appendArray(checkLiteralValueList(altNameList));

    LOGIT_DEBUG_STRINGARRAY("IssuerAlternativeNameExt::verify()", result);

    return result;
}

blocxx::StringArray
IssuerAlternativeNameExt::dump() const
{
    StringArray result;
    result.append("IssuerAlternativeNameExt::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    result.append("Issuer:copy = " + Bool(issuerCopy).toString());

    blocxx::List< LiteralValue >::const_iterator it = altNameList.begin();
    for(; it != altNameList.end(); ++it) {
        result.appendArray((*it).dump());
    }
    
    return result;
}

}
}
