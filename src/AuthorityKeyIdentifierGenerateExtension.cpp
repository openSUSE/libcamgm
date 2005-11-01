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

AuthorityKeyIdentifierGenerateExt::AuthorityKeyIdentifierGenerateExt()
    : ExtensionBase(), keyid(KeyID_none), issuer(Issuer_none)
{}

AuthorityKeyIdentifierGenerateExt::AuthorityKeyIdentifierGenerateExt(CAConfig* caConfig,
                                                                     Type type)
    : ExtensionBase(), keyid(KeyID_none), issuer(Issuer_none)
{
    // These types are not supported by this object
    if(type == E_Client_Req || type == E_Server_Req || type == E_CA_Req)
    {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = caConfig->exists(type2Section(type, true), "authorityKeyIdentifier");
    if(p)
    {
        StringArray   sp   = PerlRegEx("\\s*,\\s*")
            .split(caConfig->getValue(type2Section(type, true), "authorityKeyIdentifier"));
        if(sp[0].equalsIgnoreCase("critical"))
        {
            setCritical(true);
            sp.remove(0);
        }

        StringArray::const_iterator it = sp.begin();
        for(; it != sp.end(); ++it)
        {
            if((*it).equalsIgnoreCase("keyid")) keyid = KeyID_normal;
            else if((*it).equalsIgnoreCase("keyid:always")) keyid = KeyID_always;
            else if((*it).equalsIgnoreCase("issuer")) issuer = Issuer_normal;
            else if((*it).equalsIgnoreCase("issuer:always")) issuer = Issuer_always;
        }
    }
    setPresent(p);
}

AuthorityKeyIdentifierGenerateExt::AuthorityKeyIdentifierGenerateExt(KeyID kid,
                                                                     Issuer iss)
    : ExtensionBase(), keyid(kid), issuer(iss)
{
    setPresent(true);
}

AuthorityKeyIdentifierGenerateExt::AuthorityKeyIdentifierGenerateExt(const AuthorityKeyIdentifierGenerateExt& extension)
    : ExtensionBase(extension), keyid(extension.keyid), issuer(extension.issuer)
{}

AuthorityKeyIdentifierGenerateExt::~AuthorityKeyIdentifierGenerateExt()
{}


AuthorityKeyIdentifierGenerateExt& 
AuthorityKeyIdentifierGenerateExt::operator=(const AuthorityKeyIdentifierGenerateExt& extension)
{
    if(this == &extension) return *this;

    ExtensionBase::operator=(extension);
    keyid  = extension.keyid;
    issuer = extension.issuer;
    
    return *this;
}

void
AuthorityKeyIdentifierGenerateExt::setKeyID(KeyID kid)
{
    keyid = kid;
    setPresent(true);
}

AuthorityKeyIdentifierGenerateExt::KeyID
AuthorityKeyIdentifierGenerateExt::getKeyID() const
{
    if(!isPresent())
    {
        LOGIT_ERROR("AuthorityKeyIdentifierGenerateExt is not present");
        BLOCXX_THROW(limal::RuntimeException,
                     "AuthorityKeyIdentifierGenerateExt is not present");
    }
    return keyid;
}

void
AuthorityKeyIdentifierGenerateExt::setIssuer(Issuer iss)
{
    issuer = iss;
    setPresent(true);
}

AuthorityKeyIdentifierGenerateExt::Issuer
AuthorityKeyIdentifierGenerateExt::getIssuer() const
{
    if(!isPresent())
    {
        LOGIT_ERROR("AuthorityKeyIdentifierGenerateExt is not present");
        BLOCXX_THROW(limal::RuntimeException,
                     "AuthorityKeyIdentifierGenerateExt is not present");
    }
    return issuer;
}

void
AuthorityKeyIdentifierGenerateExt::commit2Config(CA& ca, Type type) const
{
    if(!valid())
    {
        LOGIT_ERROR("invalid AuthorityKeyIdentifierGenerateExt object");
        BLOCXX_THROW(limal::ValueException,
                     "invalid AuthorityKeyIdentifierGenerateExt object");
    }

    // These types are not supported by this object
    if(type == E_Client_Req || type == E_Server_Req || type == E_CA_Req)
    {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent())
    {
        String extString;

        if(isCritical()) extString += "critical,";

        switch(keyid)
        {
            case AuthorityKeyIdentifierGenerateExt::KeyID_normal:
                extString += "keyid,";
                break;
            case AuthorityKeyIdentifierGenerateExt::KeyID_always:
                extString += "keyid:always,";
                break;
            default:
                break;
        }

        switch(issuer)
        {
            case AuthorityKeyIdentifierGenerateExt::Issuer_normal:
                extString += "issuer,";
                break;
            case AuthorityKeyIdentifierGenerateExt::Issuer_always:
                extString += "issuer:always,";
                break;
            default:
                break;
        }

        ca.getConfig()->setValue(type2Section(type, true), "authorityKeyIdentifier",
                                 extString.erase(extString.length()-1));
    }
    else
    {
        ca.getConfig()->deleteValue(type2Section(type, true), "authorityKeyIdentifier");
    }
}

bool
AuthorityKeyIdentifierGenerateExt::valid() const
{
    if(!isPresent())
    {
        LOGIT_DEBUG("return AuthorityKeyIdentifierGenerateExt::valid() is true");
        return true;
    }
    if(keyid == KeyID_none && issuer == Issuer_none)
    {
        LOGIT_DEBUG("return AuthorityKeyIdentifierGenerateExt::valid() is false");
        return false;
    }
    LOGIT_DEBUG("return AuthorityKeyIdentifierGenerateExt::valid() is true");
    return true;
}

blocxx::StringArray
AuthorityKeyIdentifierGenerateExt::verify() const
{
    blocxx::StringArray result;

    if(!isPresent()) return result;
    if(keyid == KeyID_none && issuer == Issuer_none)
    {
        result.append(String("Invalid value for keyid and issuer. ") +
                      String("At least one of both must be set"));
    }
    LOGIT_DEBUG_STRINGARRAY("AuthorityKeyIdentifierGenerateExt::verify()", result);
    return result;
}

blocxx::StringArray
AuthorityKeyIdentifierGenerateExt::dump() const
{
    StringArray result;
    result.append("AuthorityKeyIdentifierGenerateExt::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    result.append("KeyID = " + String(keyid));
    result.append("Issuer = " + String(issuer));

    return result;
}
