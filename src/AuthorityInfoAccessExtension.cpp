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

  File:       AuthorityInfoAccessExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/AuthorityInfoAccessExtension.hpp>
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;


AuthorityInformation::AuthorityInformation()
    : accessOID(""), location(LiteralValue())
{}

AuthorityInformation::AuthorityInformation(const AuthorityInformation& ai)
    : accessOID(ai.accessOID), location(ai.location)
{}

AuthorityInformation::AuthorityInformation(const String &accessOID, 
                                           const LiteralValue& location)
    : accessOID(accessOID), location(location)
{
    if(!location.valid()) {
        LOGIT_ERROR("invalid location"); 
        BLOCXX_THROW(limal::ValueException, "invalid location");
    }
    if(!initAccessOIDCheck().isValid(accessOID)) {
        LOGIT_ERROR("invalid accessOID"); 
        BLOCXX_THROW(limal::ValueException, "invalid accessOID");
    }
}


AuthorityInformation&
AuthorityInformation::operator=(const AuthorityInformation& ai)
{
    if(this == &ai) return *this;

    accessOID = ai.accessOID;
    location  = ai.location;

    return *this;
}

void
AuthorityInformation::setAuthorityInformation(const String &accessOID, 
                                              const LiteralValue& location)
{
    if(!location.valid()) {
        LOGIT_ERROR("invalid location"); 
        BLOCXX_THROW(limal::ValueException, "invalid location");
    }
    if(!initAccessOIDCheck().isValid(accessOID)) {
        LOGIT_ERROR("invalid accessOID"); 
        BLOCXX_THROW(limal::ValueException, "invalid accessOID");
    }

    this->accessOID = accessOID;
    this->location  = location;
}

blocxx::String
AuthorityInformation::getAccessOID() const
{
    return accessOID;
}

LiteralValue
AuthorityInformation::getLocation() const
{
    return location;
}

bool
AuthorityInformation::valid() const
{
    if(!initAccessOIDCheck().isValid(accessOID)) {
        LOGIT_DEBUG("return AuthorityInformation::valid() is false"); 
        return false;
    }
    if(!location.valid()) {
        LOGIT_DEBUG("return AuthorityInformation::valid() is false"); 
        return false;
    }
    LOGIT_DEBUG("return AuthorityInformation::valid() is true"); 
    return true;
}

blocxx::StringArray
AuthorityInformation::verify() const
{
    StringArray result;
    
    if(!initAccessOIDCheck().isValid(accessOID)) {
        result.append(Format("invalid value(%1) for accessOID", accessOID).toString());
    }
    result.appendArray(location.verify());
    
    LOGIT_DEBUG_STRINGARRAY("AuthorityInformation::verify()", result);
    return result;
}

// ###############################################################################

AuthorityInfoAccessExtension::AuthorityInfoAccessExtension()
    : ExtensionBase()
{}

AuthorityInfoAccessExtension::AuthorityInfoAccessExtension(const AuthorityInfoAccessExtension& extension)
    : ExtensionBase(extension), info(extension.info)
{}

AuthorityInfoAccessExtension::AuthorityInfoAccessExtension(CA& ca, Type type)
    : ExtensionBase()
{
    // These types are not supported by this object
    if(type == Client_Req || type == Server_Req ||
       type == CA_Req     || type == CRL           ) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = ca.getConfig()->exists(type2Section(type, true), "authorityInfoAccess");
    if(p) {
        StringArray   sp   = PerlRegEx("\\s*,\\s*")
            .split(ca.getConfig()->getValue(type2Section(type, true), "authorityInfoAccess"));
        if(sp[0].equalsIgnoreCase("critical"))  setCritical(true);

        StringArray::const_iterator it = sp.begin();
        for(; it != sp.end(); ++it) {
            StringArray al = PerlRegEx(";").split(*it);

            try {
                AuthorityInformation ai = AuthorityInformation(al[0], LiteralValue(al[1]));

            } catch(blocxx::Exception& e) {
                LOGIT_ERROR("invalid value: " << *it);
            }
        }
    }
    setPresent(p);
}

AuthorityInfoAccessExtension::~AuthorityInfoAccessExtension() {}

AuthorityInfoAccessExtension& 
AuthorityInfoAccessExtension::operator=(const AuthorityInfoAccessExtension& extension)
{
    if(this == &extension) return *this;
    
    ExtensionBase::operator=(extension);
    info = extension.info;

    return *this;
}

void
AuthorityInfoAccessExtension::setAuthorityInformation(const blocxx::List<AuthorityInformation>& infolist)
{
    blocxx::List<AuthorityInformation>::const_iterator it = infolist.begin();
    for(;it != infolist.end(); it++) {
        if(!(*it).valid()) {
            LOGIT_ERROR("invalid AuthorityInformation in infolist");
            BLOCXX_THROW(limal::ValueException, "invalid AuthorityInformation in infolist");
        }
    }
    setPresent(true);
    info = infolist;
}

blocxx::List<AuthorityInformation>
AuthorityInfoAccessExtension::getAuthorityInformation() const
{
    if(!isPresent()) {
        LOGIT_ERROR("AuthorityInfoAccessExtension is not present");
        BLOCXX_THROW(limal::RuntimeException, "AuthorityInfoAccessExtension is not present");
    }
    return info;
}

void 
AuthorityInfoAccessExtension::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid AuthorityInfoAccessExtension object");
        BLOCXX_THROW(limal::ValueException, "invalid AuthorityInfoAccessExtension object");
    }

    // These types are not supported by this object
    if(type == Client_Req || type == Server_Req ||
       type == CA_Req     || type == CRL           ) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent()) {
        String extString;

        if(isCritical()) extString += "critical,";

        blocxx::List<AuthorityInformation>::const_iterator it = info.begin();
        for(;it != info.end(); ++it) {
            extString += (*it).getAccessOID() + ";" + (*it).getLocation().toString()+",";
        }

        ca.getConfig()->setValue(type2Section(type, true), "authorityInfoAccess",
                                 extString.erase(extString.length()-2));
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "authorityInfoAccess");
    }
}

bool
AuthorityInfoAccessExtension::valid() const
{
    if(!isPresent()) {
        LOGIT_DEBUG("return AuthorityInfoAccessExtension::valid() is true");
        return true;
    }

    if(info.empty()) {
        LOGIT_DEBUG("return AuthorityInfoAccessExtension::valid() is false");
        return false;
    }
    blocxx::List<AuthorityInformation>::const_iterator it = info.begin();
    for(;it != info.end(); it++) {
        if(!(*it).valid()) {
            LOGIT_DEBUG("return AuthorityInfoAccessExtension::valid() is false");
            return false;
        }
    }
    LOGIT_DEBUG("return AuthorityInfoAccessExtension::valid() is true");
    return true;
}

blocxx::StringArray
AuthorityInfoAccessExtension::verify() const
{
    blocxx::StringArray result;

    if(!isPresent()) return result;
    
    if(info.empty()) {
        result.append(String("No access informations available"));
    }
    blocxx::List<AuthorityInformation>::const_iterator it = info.begin();
    for(;it != info.end(); it++) {
        result.appendArray((*it).verify());
    }

    LOGIT_DEBUG_STRINGARRAY("AuthorityInfoAccessExtension::verify()", result);
    return result;
}
