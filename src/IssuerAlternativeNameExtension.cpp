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
#include  <limal/Exception.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;


IssuerAlternativeNameExtension::IssuerAlternativeNameExtension()
    :ExtensionBase(), issuerCopy(false), altNameList(blocxx::List<LiteralValueBase>())
{}

IssuerAlternativeNameExtension::IssuerAlternativeNameExtension(bool copyIssuer, 
                                                               const blocxx::List<LiteralValueBase> &alternativeNameList)
    :ExtensionBase(), issuerCopy(copyIssuer), altNameList(alternativeNameList)
{
    if(!issuerCopy && altNameList.empty()) {
        LOGIT_ERROR("invalid value for IssuerAlternativeNameExtension");
        BLOCXX_THROW(limal::ValueException, "invalid value for IssuerAlternativeNameExtension");
    }
    blocxx::List<LiteralValueBase>::const_iterator it = altNameList.begin();
    for(;it != altNameList.end(); it++) {
        if(!(*it).valid()) {
            LOGIT_ERROR("invalid literal value for IssuerAlternativeNameExtension");
            BLOCXX_THROW(limal::ValueException, 
                         "invalid literal value for IssuerAlternativeNameExtension");
        }
    }
    setPresent(true);
}

IssuerAlternativeNameExtension::IssuerAlternativeNameExtension(CA& ca, Type type)
    :ExtensionBase(), issuerCopy(false), altNameList(blocxx::List<LiteralValueBase>())
{
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
    if(!copyIssuer && altNameList.empty()) {
        LOGIT_ERROR("invalid value for IssuerAlternativeNameExtension");
        BLOCXX_THROW(limal::ValueException, "invalid value for IssuerAlternativeNameExtension");
    }
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
IssuerAlternativeNameExtension::setAlternativeNameList(const blocxx::List<LiteralValueBase> &alternativeNameList)
{
    if(!issuerCopy && alternativeNameList.empty()) {
        LOGIT_ERROR("invalid value for IssuerAlternativeNameExtension");
        BLOCXX_THROW(limal::ValueException, "invalid value for IssuerAlternativeNameExtension");
    }

    blocxx::List<LiteralValueBase>::const_iterator it = alternativeNameList.begin();
    for(;it != alternativeNameList.end(); it++) {
        if(!(*it).valid()) {
            LOGIT_ERROR("invalid literal value for IssuerAlternativeNameExtension");
            BLOCXX_THROW(limal::ValueException, 
                         "invalid literal value for IssuerAlternativeNameExtension");
        }
    }
    altNameList = alternativeNameList;
    setPresent(true);
}

blocxx::List<LiteralValueBase>
IssuerAlternativeNameExtension::getAlternativeNameList() const
{
    if(!isPresent()) {
        LOGIT_ERROR("IssuerAlternativeNameExtension is not present");
        BLOCXX_THROW(limal::RuntimeException, "IssuerAlternativeNameExtension is not present");
    }
    return altNameList;
}

void
IssuerAlternativeNameExtension::addIssuerAltName(const LiteralValueBase& altName)
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
IssuerAlternativeNameExtension::commit2Config(CA& ca, Type type)
{
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
    blocxx::List<LiteralValueBase>::const_iterator it = altNameList.begin();
    for(;it != altNameList.end(); it++) {
        if(!(*it).valid()) {
            LOGIT_DEBUG("return IssuerAlternativeNameExtension::valid() ist false");
            return false;
        }
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
    blocxx::List<LiteralValueBase>::const_iterator it = altNameList.begin();
    for(;it != altNameList.end(); it++) {
        result.appendArray((*it).verify());
    }
    LOGIT_DEBUG_STRINGARRAY("IssuerAlternativeNameExtension::verify()", result);
    return result;
}
