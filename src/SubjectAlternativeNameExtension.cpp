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
}

SubjectAlternativeNameExtension::SubjectAlternativeNameExtension(bool copyEmail,
                                     const blocxx::List<LiteralValue> &alternativeNameList)
    : ExtensionBase(), emailCopy(copyEmail), altNameList(alternativeNameList)
{
    StringArray r = this->verify();
    if(!r.empty()) {
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
    bool                       oldEmailCopy   = emailCopy;
    blocxx::List<LiteralValue> oldAltNameList = altNameList;

    emailCopy = copyEmail;
    altNameList = alternativeNameList;

    StringArray r = this->verify();
    if(!r.empty()) {
        emailCopy   = oldEmailCopy;
        altNameList = oldAltNameList;

        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
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
SubjectAlternativeNameExtension::commit2Config(CA& ca, Type type)
{
}

bool
SubjectAlternativeNameExtension::valid() const
{
    if(!isPresent()) return true;

    if(!emailCopy && altNameList.empty()) {
        LOGIT_DEBUG("return SubjectAlternativeNameExtension::::valid() is false");
        return false;
    }
    blocxx::List<LiteralValue>::const_iterator it = altNameList.begin();
    for(;it != altNameList.end(); it++) {
        if(!(*it).valid()) {
            LOGIT_DEBUG("return IssuerAlternativeNameExtension::valid() is false");
            return false;
        }
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
    blocxx::List<LiteralValue>::const_iterator it = altNameList.begin();
    for(;it != altNameList.end(); it++) {
        result.appendArray((*it).verify());
    }
    LOGIT_DEBUG_STRINGARRAY("SubjectAlternativeNameExtension::verify()", result);
    
    return result;
}
