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
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;


inline static ValueCheck initValueCheck() {
    ValueCheck checkAccessOID =
        ValueCheck(new ValueRegExCheck("^(OCSP|caIssuers)$"))
        .Or(new ValueRegExCheck("^([0-9]+\\.)+[0-9]+$"));

    return checkAccessOID;
}

AuthorityInformation::AuthorityInformation()
    : accessOID(""), location(LiteralValueBase())
{
}

AuthorityInformation::AuthorityInformation(const AuthorityInformation& ai)
    : accessOID(ai.accessOID), location(ai.location)
{
    if(!location.valid()) {
        BLOCXX_THROW(limal::ValueException, "invalid location");
    }
    if(!valid()) {
        BLOCXX_THROW(limal::ValueException, "invalid accessOID");
    }
}

AuthorityInformation::AuthorityInformation(const String &accessOID, 
                                           const LiteralValueBase& location)
    : accessOID(accessOID), location(location)
{
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
                                              const LiteralValueBase& location)
{
    if(!location.valid()) {
        BLOCXX_THROW(limal::ValueException, "invalid location");
    }
    if(!initValueCheck().isValid(accessOID)) {
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

LiteralValueBase
AuthorityInformation::getLocation() const
{
    return location;
}

bool
AuthorityInformation::valid() const
{
    ValueCheck checkAccessOID = initValueCheck();
    if(!checkAccessOID.isValid(accessOID)) {
        return false;
    }
    if(!location.valid()) {
        return false;
    }
    return true;
}

blocxx::StringArray
AuthorityInformation::verify() const
{
    StringArray result;
    
    ValueCheck checkAccessOID = initValueCheck();
    
    if(!checkAccessOID.isValid(accessOID)) {
        result.append(Format("invalid value(%1) for accessOID", accessOID).toString());
    }
    result.appendArray(location.verify());

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
    //Parse the config file
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
    if(infolist.empty()) {
        BLOCXX_THROW(limal::ValueException, "empty infolist");
    }
    blocxx::List<AuthorityInformation>::const_iterator it = infolist.begin();
    for(;it != infolist.end(); it++) {
        if(!(*it).valid()) {
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
        BLOCXX_THROW(limal::RuntimeException, "AuthorityInfoAccessExtension is not present");
    }
    return info;
}

void 
AuthorityInfoAccessExtension::commit2Config(CA& ca, Type type)
{
    if(!isPresent()) {
        return;
    }

}

bool
AuthorityInfoAccessExtension::valid() const
{
    if(!isPresent()) return true;

    if(info.empty()) {
        return false;
    }
    blocxx::List<AuthorityInformation>::const_iterator it = info.begin();
    for(;it != info.end(); it++) {
        if(!(*it).valid()) {
            return false;
        }
    }
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
    return result;
}
