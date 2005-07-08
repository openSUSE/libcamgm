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

  File:       SubjectKeyIdentifierExtension.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/SubjectKeyIdentifierExtension.hpp>
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

SubjectKeyIdentifierExtension::SubjectKeyIdentifierExtension()
    : ExtensionBase(), autodetect(false), keyid(String())
{}

SubjectKeyIdentifierExtension::SubjectKeyIdentifierExtension(CA& ca, Type type)
    : ExtensionBase(), autodetect(false), keyid(String())
{
    // These types are not supported by this object
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = ca.getConfig()->exists(type2Section(type, true), "subjectKeyIdentifier");
    if(p) {
        String        str;

        StringArray   sp   = PerlRegEx("\\s*,\\s*")
            .split(ca.getConfig()->getValue(type2Section(type, true), "subjectKeyIdentifier"));
        if(sp[0].equalsIgnoreCase("critical")) {
            setCritical(true);
            str = sp[1];
        } else {
            str = sp[0];
        }

        if(str.equalsIgnoreCase("hash")) {
            this->autodetect = true;
            this->keyid      = String();
        } else {
            this->autodetect = false;
            this->keyid      = str;
        }
    }
    setPresent(p);
}

SubjectKeyIdentifierExtension::SubjectKeyIdentifierExtension(bool autoDetect, const String& keyid)
    : ExtensionBase(), autodetect(autoDetect), keyid(keyid)
{
    if(!keyid.empty() && !initHexCheck().isValid(keyid)) {
        LOGIT_ERROR("invalid KeyID");
        BLOCXX_THROW(limal::ValueException, "invalid KeyID");
    }
    setPresent(true);
}

SubjectKeyIdentifierExtension::SubjectKeyIdentifierExtension(const SubjectKeyIdentifierExtension& extension)
    : ExtensionBase(extension), autodetect(extension.autodetect), keyid(extension.keyid)
{}

SubjectKeyIdentifierExtension::~SubjectKeyIdentifierExtension()
{}


SubjectKeyIdentifierExtension&
SubjectKeyIdentifierExtension::operator=(const SubjectKeyIdentifierExtension& extension)
{
    if(this == &extension) return *this;
    
    ExtensionBase::operator=(extension);
    
    autodetect = extension.autodetect;
    keyid      = extension.keyid;
    
    return *this;
}

void
SubjectKeyIdentifierExtension::setSubjectKeyIdentifier(bool autoDetect,
                                                       const String& keyId)
{
    if(!keyId.empty() && !initHexCheck().isValid(keyId)) {
        LOGIT_ERROR("invalid KeyID");
        BLOCXX_THROW(limal::ValueException, "invalid KeyID");
    }
    this->autodetect = autoDetect;
    this->keyid      = keyId;
    setPresent(true);
}

bool
SubjectKeyIdentifierExtension::isAutoDetectionEnabled() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "SubjectKeyIdentifierExtension is not present");
    }
    return autodetect;
}

blocxx::String
SubjectKeyIdentifierExtension::getKeyID() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "SubjectKeyIdentifierExtension is not present");
    }
    return keyid;
}


void
SubjectKeyIdentifierExtension::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid SubjectKeyIdentifierExtension object");
        BLOCXX_THROW(limal::ValueException, "invalid SubjectKeyIdentifierExtension object");
    }

    // This extension is not supported by type CRL
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent()) {
        String extString;

        if(isCritical()) extString += "critical,";
        if(autodetect) {
            extString += "hash";
        } else {
            extString += keyid;
        }

        ca.getConfig()->setValue(type2Section(type, true), "subjectKeyIdentifier", extString);
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "subjectKeyIdentifier");
    }
}

bool
SubjectKeyIdentifierExtension::valid() const
{
    if(!isPresent()) return true;

    if(!autodetect && keyid.empty()) {
        LOGIT_DEBUG(Format("Wrong value for SubjectKeyIdentifierExtension: autodetect(%1), keyId(%2)",
                           autodetect?"true":"false", keyid));
        return false;
    }

    if(autodetect && !keyid.empty()) {
        LOGIT_DEBUG(Format("Wrong value for SubjectKeyIdentifierExtension: autodetect(%1), keyId(%2)",
                           autodetect?"true":"false", keyid));
        return false;
    }
    if(!keyid.empty()) {
        ValueCheck check = initHexCheck();
        if(!check.isValid(keyid)) {
            LOGIT_DEBUG("Wrong keyID in SubjectKeyIdentifierExtension:" << keyid);
            return false;
        }
    }
    return true;
}

blocxx::StringArray
SubjectKeyIdentifierExtension::verify() const
{
    StringArray result;

    if(!isPresent()) return result;

    if(!autodetect && keyid.empty()) {
        result.append(Format("Wrong value for SubjectKeyIdentifierExtension: autodetect(%1), keyId(%2)", 
                             autodetect?"true":"false", keyid.c_str()).toString());
    }

    if(autodetect && !keyid.empty()) {
        result.append(Format("Wrong value for SubjectKeyIdentifierExtension: autodetect(%1), keyId(%2)", 
                             autodetect?"true":"false", keyid.c_str()).toString());
    }
    if(!keyid.empty()) {
        ValueCheck check = initHexCheck();
        if(!check.isValid(keyid)) {
            result.append(Format("Wrong keyID in SubjectKeyIdentifierExtension: %1",
                                 keyid.c_str()).toString());
        }
    }
    LOGIT_DEBUG_STRINGARRAY("SubjectKeyIdentifierExtension::verify()", result);
    return result;
}

blocxx::StringArray
SubjectKeyIdentifierExtension::dump() const
{
    StringArray result;
    result.append("SubjectKeyIdentifierExtension::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    result.append("Autodetect = " + Bool(autodetect).toString());
    result.append("KeyID = " + keyid);

    return result;
}

