
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

  File:       SubjectAlternativeNameExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/SubjectAlternativeNameExtension.hpp>
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/Exception.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

SubjectAlternativeNameExtension::SubjectAlternativeNameExtension()
    : ExtensionBase(), emailCopy(false), altNameList(blocxx::List<LiteralValue>())
{}

SubjectAlternativeNameExtension::SubjectAlternativeNameExtension(CA& ca, Type type)
    : ExtensionBase(), emailCopy(false), altNameList(blocxx::List<LiteralValue>())
{
    // These types are not supported by this object
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = ca.getConfig()->exists(type2Section(type, true), "subjectAltName");
    if(p) {
        StringArray   sp   = PerlRegEx("\\s*,\\s*")
            .split(ca.getConfig()->getValue(type2Section(type, true), "subjectAltName"));
        if(sp[0].equalsIgnoreCase("critical"))  setCritical(true);

        StringArray::const_iterator it = sp.begin();
        for(; it != sp.end(); ++it) {
            if((*it).indexOf(":") != String::npos) {
                if((*it).equalsIgnoreCase("email:copy"))  
                    emailCopy = true;
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

SubjectAlternativeNameExtension::SubjectAlternativeNameExtension(bool copyEmail,
                                     const blocxx::List<LiteralValue> &alternativeNameList)
    : ExtensionBase(), emailCopy(copyEmail), altNameList(alternativeNameList)
{
    StringArray r = checkLiteralValueList(alternativeNameList);
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    setPresent(true);
}

SubjectAlternativeNameExtension::SubjectAlternativeNameExtension(const SubjectAlternativeNameExtension& extension)
    : ExtensionBase(extension), emailCopy(extension.emailCopy), altNameList(extension.altNameList)
{}


SubjectAlternativeNameExtension::~SubjectAlternativeNameExtension()
{}


SubjectAlternativeNameExtension&
SubjectAlternativeNameExtension::operator=(const SubjectAlternativeNameExtension& extension)
{
    if(this == &extension) return *this;
    
    ExtensionBase::operator=(extension);
    
    emailCopy   = extension.emailCopy;
    altNameList = extension.altNameList;

    return *this;
}

void
SubjectAlternativeNameExtension::setSubjectAlternativeName(bool copyEmail, 
                               const blocxx::List<LiteralValue> &alternativeNameList)
{
    StringArray r = checkLiteralValueList(alternativeNameList);
    if(!r.empty()) {
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
    emailCopy = copyEmail;
    altNameList = alternativeNameList;
    setPresent(true);
}

bool
SubjectAlternativeNameExtension::getCopyEmail() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "SubjectAlternativeNameExtension is not present");
    }
    return emailCopy;
}

blocxx::List<LiteralValue>
SubjectAlternativeNameExtension::getAlternativeNameList() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "SubjectAlternativeNameExtension is not present");
    }
    return altNameList;
}


void
SubjectAlternativeNameExtension::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid SubjectAlternativeNameExtension object");
        BLOCXX_THROW(limal::ValueException, "invalid SubjectAlternativeNameExtension object");
    }

    // This extension is not supported by type CRL
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent()) {
        String extString;

        if(isCritical()) extString += "critical,";
        if(emailCopy) {
            extString += "email:copy,";
        }
        blocxx::List<LiteralValue>::const_iterator it = altNameList.begin();
        for(;it != altNameList.end(); ++it) {
            extString += (*it).toString()+",";
        }

        ca.getConfig()->setValue(type2Section(type, true), "subjectAltName", 
                                 extString.erase(extString.length()-2));
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "subjectAltName");
    }
}

bool
SubjectAlternativeNameExtension::valid() const
{
    if(!isPresent()) return true;

    if(!emailCopy && altNameList.empty()) {
        LOGIT_DEBUG("return SubjectAlternativeNameExtension::::valid() is false");
        return false;
    }
    StringArray r = checkLiteralValueList(altNameList);
    if(!r.empty()) {
        LOGIT_DEBUG(r[0]);
        return false;
    }
    return true;
}

blocxx::StringArray
SubjectAlternativeNameExtension::verify() const
{
    StringArray result;

    if(!isPresent()) return result;

    if(!emailCopy && altNameList.empty()) {
        result.append(String("invalid value for SubjectAlternativeNameExtension"));
    }
    result.appendArray(checkLiteralValueList(altNameList));

    LOGIT_DEBUG_STRINGARRAY("SubjectAlternativeNameExtension::verify()", result);
    
    return result;
}

blocxx::StringArray
SubjectAlternativeNameExtension::dump() const
{
    StringArray result;
    result.append("SubjectAlternativeNameExtension::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    result.append("email:copy = " + Bool(emailCopy).toString());

    blocxx::List< LiteralValue >::const_iterator it = altNameList.begin();
    for(; it != altNameList.end(); ++it) {
        result.appendArray((*it).dump());
    }

    return result;
}
