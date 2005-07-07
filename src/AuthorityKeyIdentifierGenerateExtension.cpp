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

  File:       AuthorityKeyIdentifierGenerateExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/AuthorityKeyIdentifierGenerateExtension.hpp>
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/Exception.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

AuthorityKeyIdentifierGenerateExtension::AuthorityKeyIdentifierGenerateExtension()
    : ExtensionBase(), keyid(KeyID_none), issuer(Issuer_none)
{}

AuthorityKeyIdentifierGenerateExtension::AuthorityKeyIdentifierGenerateExtension(CA& ca, Type type)
    : ExtensionBase(), keyid(KeyID_none), issuer(Issuer_none)
{
    // These types are not supported by this object
    if(type == Client_Req || type == Server_Req || type == CA_Req) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = ca.getConfig()->exists(type2Section(type, true), "authorityKeyIdentifier");
    if(p) {
        StringArray   sp   = PerlRegEx("\\s*,\\s*")
            .split(ca.getConfig()->getValue(type2Section(type, true), "authorityKeyIdentifier"));
        if(sp[0].equalsIgnoreCase("critical")) {
            setCritical(true);
            sp.remove(0);
        }

        StringArray::const_iterator it = sp.begin();
        for(; it != sp.end(); ++it) {

            if((*it).equalsIgnoreCase("keyid")) keyid = KeyID_normal;
            else if((*it).equalsIgnoreCase("keyid:always")) keyid = KeyID_always;
            else if((*it).equalsIgnoreCase("issuer")) issuer = Issuer_normal;
            else if((*it).equalsIgnoreCase("issuer:always")) issuer = Issuer_always;
            
        }
    }
    setPresent(p);
}

AuthorityKeyIdentifierGenerateExtension::AuthorityKeyIdentifierGenerateExtension(KeyID kid, Issuer iss)
    : ExtensionBase(), keyid(kid), issuer(iss)
{
    setPresent(true);
}

AuthorityKeyIdentifierGenerateExtension::AuthorityKeyIdentifierGenerateExtension(const AuthorityKeyIdentifierGenerateExtension& extension)
    : ExtensionBase(extension), keyid(extension.keyid), issuer(extension.issuer)
{}

AuthorityKeyIdentifierGenerateExtension::~AuthorityKeyIdentifierGenerateExtension()
{}


AuthorityKeyIdentifierGenerateExtension& 
AuthorityKeyIdentifierGenerateExtension::operator=(const AuthorityKeyIdentifierGenerateExtension& extension)
{
    if(this == &extension) return *this;

    ExtensionBase::operator=(extension);
    keyid  = extension.keyid;
    issuer = extension.issuer;
    
    return *this;
}

void
AuthorityKeyIdentifierGenerateExtension::setKeyID(KeyID kid)
{
    keyid = kid;
    setPresent(true);
}

AuthorityKeyIdentifierGenerateExtension::KeyID
AuthorityKeyIdentifierGenerateExtension::getKeyID() const
{
    if(!isPresent()) {
        LOGIT_ERROR("AuthorityKeyIdentifierGenerateExtension is not present");
        BLOCXX_THROW(limal::RuntimeException, "AuthorityKeyIdentifierGenerateExtension is not present");
    }
    return keyid;
}

void
AuthorityKeyIdentifierGenerateExtension::setIssuer(Issuer iss)
{
    issuer = iss;
    setPresent(true);
}

AuthorityKeyIdentifierGenerateExtension::Issuer
AuthorityKeyIdentifierGenerateExtension::getIssuer() const
{
    if(!isPresent()) {
        LOGIT_ERROR("AuthorityKeyIdentifierGenerateExtension is not present");
        BLOCXX_THROW(limal::RuntimeException, "AuthorityKeyIdentifierGenerateExtension is not present");
    }
    return issuer;
}

void
AuthorityKeyIdentifierGenerateExtension::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid AuthorityKeyIdentifierGenerateExtension object");
        BLOCXX_THROW(limal::ValueException, "invalid AuthorityKeyIdentifierGenerateExtension object");
    }

    // These types are not supported by this object
    if(type == Client_Req || type == Server_Req || type == CA_Req) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent()) {
        String extString;

        if(isCritical()) extString += "critical,";

        switch(keyid) {
        case AuthorityKeyIdentifierGenerateExtension::KeyID_normal:
            extString += "keyid,";
            break;
        case AuthorityKeyIdentifierGenerateExtension::KeyID_always:
            extString += "keyid:always,";
            break;
        default:
            break;
        }

        switch(issuer) {
        case AuthorityKeyIdentifierGenerateExtension::Issuer_normal:
            extString += "issuer,";
            break;
        case AuthorityKeyIdentifierGenerateExtension::Issuer_always:
            extString += "issuer:always,";
            break;
        default:
            break;
        }

        ca.getConfig()->setValue(type2Section(type, true), "authorityKeyIdentifier",
                                 extString.erase(extString.length()-2));
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "authorityKeyIdentifier");
    }
}

bool
AuthorityKeyIdentifierGenerateExtension::valid() const
{
    if(!isPresent()) {
        LOGIT_DEBUG("return AuthorityKeyIdentifierGenerateExtension::valid() is true");
        return true;
    }
    if(keyid == KeyID_none && issuer == Issuer_none) {
        LOGIT_DEBUG("return AuthorityKeyIdentifierGenerateExtension::valid() is false");
        return false;
    }
    LOGIT_DEBUG("return AuthorityKeyIdentifierGenerateExtension::valid() is true");
    return true;
}

blocxx::StringArray
AuthorityKeyIdentifierGenerateExtension::verify() const
{
    blocxx::StringArray result;

    if(!isPresent()) return result;
    if(keyid == KeyID_none && issuer == Issuer_none) {
        result.append(String("Invalid value for keyid and issuer. At least one of both must be set"));
    }
    LOGIT_DEBUG_STRINGARRAY("AuthorityKeyIdentifierGenerateExtension::verify()", result);
    return result;
}

blocxx::StringArray
AuthorityKeyIdentifierGenerateExtension::dump() const
{
    StringArray result;
    result.append("AuthorityKeyIdentifierGenerateExtension::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    result.append("KeyID = " + String(keyid));
    result.append("Issuer = " + String(issuer));

    return result;
}
