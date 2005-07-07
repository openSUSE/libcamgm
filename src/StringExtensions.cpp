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

  File:       StringExtensions.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/

#include  <limal/ca-mgm/StringExtensions.hpp>
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

StringExtension::StringExtension()
    : ExtensionBase(), value(String())
{}
       
StringExtension::~StringExtension()
{}

        
//    protected:

StringExtension::StringExtension(const String &v ) 
    : ExtensionBase(), value(v) 
{}

StringExtension::StringExtension(const StringExtension& extension)
    : ExtensionBase(extension), value(extension.value) 
{}
        
StringExtension&
StringExtension::operator=(const StringExtension& extension)
{
    if(this == &extension) return *this;

    ExtensionBase::operator=(extension);
    value = extension.value;

    return *this;
}
        

// #################################################################

NsBaseUrlExtension::NsBaseUrlExtension(const String &v)
    : StringExtension(v)
{
    if(!initURICheck().isValid(getValue())) {
        LOGIT_ERROR("invalid value for NsBaseUrlExtension");
        BLOCXX_THROW(limal::ValueException, "invalid value for NsBaseUrlExtension");
    }
    setPresent(true);
}

NsBaseUrlExtension::NsBaseUrlExtension(CA& ca, Type type)
    : StringExtension(String())
{
    // These types are not supported by this object
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = ca.getConfig()->exists(type2Section(type, true), "nsBaseUrl");
    if(p) {
        StringArray   sp   = PerlRegEx("\\s*,\\s*")
            .split(ca.getConfig()->getValue(type2Section(type, true), "nsBaseUrl"));
        if(sp[0].equalsIgnoreCase("critical")) {
            setCritical(true); 
            value = sp[1];
        } else {
            value = sp[0];
        }
    }
    setPresent(p);
}

NsBaseUrlExtension::NsBaseUrlExtension(const NsBaseUrlExtension &extension)
    : StringExtension(extension)
{}

NsBaseUrlExtension::~NsBaseUrlExtension()
{}

NsBaseUrlExtension&
NsBaseUrlExtension::operator=(const NsBaseUrlExtension& extension)
{
    if(this == &extension) return *this;

    StringExtension::operator=(extension);

    return *this;
}

void
NsBaseUrlExtension::setValue(const String &v)
{
    if(!initURICheck().isValid(v)) {
        LOGIT_ERROR("invalid value for NsBaseUrlExtension");
        BLOCXX_THROW(limal::ValueException, "invalid value for NsBaseUrlExtension");
    }
    value = v;
    setPresent(true);
}

blocxx::String
NsBaseUrlExtension::getValue() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "NsBaseUrlExtension is not present");
    }
    return value;
}

void
NsBaseUrlExtension::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid NsBaseUrlExtension object");
        BLOCXX_THROW(limal::ValueException, "invalid NsBaseUrlExtension object");
    }

    // This extension is not supported by type CRL
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent()) {
        String extString;

        if(isCritical()) extString += "critical,";
        extString += value;

        ca.getConfig()->setValue(type2Section(type, true), "nsBaseUrl", extString);
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "nsBaseUrl");
    }
}

bool
NsBaseUrlExtension::valid() const
{
    if(!isPresent()) return true;

    if(!initURICheck().isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsBaseUrlExtension:" << value);
        return false;
    }    
    return true;
}

blocxx::StringArray
NsBaseUrlExtension::verify() const
{
    StringArray result;

    if(!isPresent()) return result;

    if(!initURICheck().isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsBaseUrlExtension:" << value);
        result.append(Format("Wrong value for NsBaseUrlExtension: %1", value).toString());
    }
    return result;
}

blocxx::StringArray
NsBaseUrlExtension::dump() const
{
    StringArray result;
    result.append("NsBaseUrlExtension::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    result.append("URL = " + value);

    return result;
}


// private:
NsBaseUrlExtension::NsBaseUrlExtension()
    : StringExtension(String())
{}


// #################################################################

NsRevocationUrlExtension::NsRevocationUrlExtension(const String &v)
    : StringExtension(v)
{
    if(!initURICheck().isValid(v)) {
        LOGIT_ERROR("invalid value for NsRevocationUrlExtension");
        BLOCXX_THROW(limal::ValueException, "invalid value for NsRevocationUrlExtension");
    }
    setPresent(true);
}

NsRevocationUrlExtension::NsRevocationUrlExtension(CA& ca, Type type)
    : StringExtension(String())
{
    // These types are not supported by this object
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }
    
    bool p = ca.getConfig()->exists(type2Section(type, true), "nsRevocationUrl");
    if(p) {
        StringArray   sp   = PerlRegEx("\\s*,\\s*")
            .split(ca.getConfig()->getValue(type2Section(type, true), "nsRevocationUrl"));
        if(sp[0].equalsIgnoreCase("critical")) {
            setCritical(true); 
            value = sp[1];
        } else {
            value = sp[0];
        }
    }
    setPresent(p);
}

NsRevocationUrlExtension::NsRevocationUrlExtension(const NsRevocationUrlExtension &extension)
    : StringExtension(extension)
{}

NsRevocationUrlExtension::~NsRevocationUrlExtension()
{}

NsRevocationUrlExtension&
NsRevocationUrlExtension::operator=(const NsRevocationUrlExtension& extension)
{
    if(this == &extension) return *this;

    StringExtension::operator=(extension);

    return *this;
}

void
NsRevocationUrlExtension::setValue(const String &v)
{
    if(!initURICheck().isValid(v)) {
        LOGIT_ERROR("invalid value for NsRevocationUrlExtension");
        BLOCXX_THROW(limal::ValueException, "invalid value for NsRevocationUrlExtension");
    }
    value = v;
    setPresent(true);
}

blocxx::String
NsRevocationUrlExtension::getValue() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "NsRevocationUrlExtension is not present");
    }
    return value;
}

void
NsRevocationUrlExtension::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid NsRevocationUrlExtension object");
        BLOCXX_THROW(limal::ValueException, "invalid NsRevocationUrlExtension object");
    }

    // This extension is not supported by type CRL
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent()) {
        String extString;

        if(isCritical()) extString += "critical,";
        extString += value;

        ca.getConfig()->setValue(type2Section(type, true), "nsRevocationUrl", extString);
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "nsRevocationUrl");
    }
}

blocxx::StringArray
NsRevocationUrlExtension::verify() const
{
    StringArray result;

    if(!isPresent()) return result;

    if(!initURICheck().isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsRevocationUrlExtension:" << value);
        result.append(Format("Wrong value for NsRevocationUrlExtension: %1", value).toString());
    }
    return result;
}

bool
NsRevocationUrlExtension::valid() const
{
    if(!isPresent()) return true;

    if(!initURICheck().isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsRevocationUrlExtension:" << value);
        return false;
    }    
    return true;
}

blocxx::StringArray
NsRevocationUrlExtension::dump() const
{
    StringArray result;
    result.append("NsRevocationUrlExtension::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    result.append("URL = " + value);

    return result;
}

//    private:
NsRevocationUrlExtension::NsRevocationUrlExtension()
    : StringExtension(String())
{
}


// #################################################################

NsCaRevocationUrlExtension::NsCaRevocationUrlExtension(const String &v)
    : StringExtension(v)
{
    if(!initURICheck().isValid(v)) {
        LOGIT_ERROR("invalid value for NsCaRevocationUrlExtension");
        BLOCXX_THROW(limal::ValueException, "invalid value for NsCaRevocationUrlExtension");
    }
    setPresent(true);
}

NsCaRevocationUrlExtension::NsCaRevocationUrlExtension(CA& ca, Type type)
    : StringExtension(String())
{
    // These types are not supported by this object
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = ca.getConfig()->exists(type2Section(type, true), "nsCaRevocationUrl");
    if(p) {
        StringArray   sp   = PerlRegEx("\\s*,\\s*")
            .split(ca.getConfig()->getValue(type2Section(type, true), "nsCaRevocationUrl"));
        if(sp[0].equalsIgnoreCase("critical")) {
            setCritical(true); 
            value = sp[1];
        } else {
            value = sp[0];
        }
    }
    setPresent(p);
}

NsCaRevocationUrlExtension::NsCaRevocationUrlExtension(const NsCaRevocationUrlExtension &extension)
    : StringExtension(extension)
{}

NsCaRevocationUrlExtension::~NsCaRevocationUrlExtension()
{}

NsCaRevocationUrlExtension&
NsCaRevocationUrlExtension::operator=(const NsCaRevocationUrlExtension& extension)
{
    if(this == &extension) return *this;

    StringExtension::operator=(extension);

    return *this;
}

void
NsCaRevocationUrlExtension::setValue(const String &v)
{
    if(!initURICheck().isValid(v)) {
        LOGIT_ERROR("invalid value for NsCaRevocationUrlExtension");
        BLOCXX_THROW(limal::ValueException, "invalid value for NsCaRevocationUrlExtension");
    }
    value = v;
    setPresent(true);
}

blocxx::String
NsCaRevocationUrlExtension::getValue() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "NsCaRevocationUrlExtension is not present");
    }
    return value;
}

void
NsCaRevocationUrlExtension::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid NsCaRevocationUrlExtension object");
        BLOCXX_THROW(limal::ValueException, "invalid NsCaRevocationUrlExtension object");
    }

    // This extension is not supported by type CRL
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent()) {
        String extString;

        if(isCritical()) extString += "critical,";
        extString += value;

        ca.getConfig()->setValue(type2Section(type, true), "nsCaRevocationUrl", extString);
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "nsCaRevocationUrl");
    }
}

blocxx::StringArray
NsCaRevocationUrlExtension::verify() const
{
    StringArray result;

    if(!isPresent()) return result;

    if(!initURICheck().isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsCaRevocationUrlExtension:" << value);
        result.append(Format("Wrong value for NsCaRevocationUrlExtension: %1", value).toString());
    }
    return result;
}

bool
NsCaRevocationUrlExtension::valid() const
{
    if(!isPresent()) return true;

    if(!initURICheck().isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsCaRevocationUrlExtension:" << value);
        return false;
    }    
    return true;
}

blocxx::StringArray
NsCaRevocationUrlExtension::dump() const
{
    StringArray result;
    result.append("NsCaRevocationUrlExtension::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    result.append("URL = " + value);

    return result;
}

//  private:
NsCaRevocationUrlExtension::NsCaRevocationUrlExtension()
    : StringExtension(String())
{}


// #################################################################

NsRenewalUrlExtension::NsRenewalUrlExtension(const String &v)
    : StringExtension(v)
{
    if(!initURICheck().isValid(v)) {
        LOGIT_ERROR("invalid value for NsRenewalUrlExtension");
        BLOCXX_THROW(limal::ValueException, "invalid value for NsRenewalUrlExtension");
    }
    setPresent(true);
}

NsRenewalUrlExtension::NsRenewalUrlExtension(CA& ca, Type type)
    : StringExtension(String())
{
    // These types are not supported by this object
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = ca.getConfig()->exists(type2Section(type, true), "nsRenewalUrl");
    if(p) {
        StringArray   sp   = PerlRegEx("\\s*,\\s*")
            .split(ca.getConfig()->getValue(type2Section(type, true), "nsRenewalUrl"));
        if(sp[0].equalsIgnoreCase("critical")) {
            setCritical(true); 
            value = sp[1];
        } else {
            value = sp[0];
        }
    }
    setPresent(p);
}

NsRenewalUrlExtension::NsRenewalUrlExtension(const NsRenewalUrlExtension &extension)
    : StringExtension(extension)
{}

NsRenewalUrlExtension::~NsRenewalUrlExtension()
{}

NsRenewalUrlExtension&
NsRenewalUrlExtension::operator=(const NsRenewalUrlExtension& extension)
{
    if(this == &extension) return *this;

    StringExtension::operator=(extension);

    return *this;
}

void
NsRenewalUrlExtension::setValue(const String &v)
{
    if(!initURICheck().isValid(v)) {
        LOGIT_ERROR("invalid value for NsRenewalUrlExtension");
        BLOCXX_THROW(limal::ValueException, "invalid value for NsRenewalUrlExtension");
    }
    value = v;
    setPresent(true);
}

blocxx::String
NsRenewalUrlExtension::getValue() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "NsRenewalUrlExtension is not present");
    }
    return value;
}

void
NsRenewalUrlExtension::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid NsRenewalUrlExtension object");
        BLOCXX_THROW(limal::ValueException, "invalid NsRenewalUrlExtension object");
    }

    // This extension is not supported by type CRL
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent()) {
        String extString;

        if(isCritical()) extString += "critical,";
        extString += value;

        ca.getConfig()->setValue(type2Section(type, true), "nsRenewalUrl", extString);
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "nsRenewalUrl");
    }
}

blocxx::StringArray
NsRenewalUrlExtension::verify() const
{
    StringArray result;

    if(!isPresent()) return result;

    if(!initURICheck().isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsRenewalUrlExtension:" << value);
        result.append(Format("Wrong value for NsRenewalUrlExtension: %1", value).toString());
    }
    return result;
}

bool
NsRenewalUrlExtension::valid() const
{
    if(!isPresent()) return true;

    if(!initURICheck().isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsRenewalUrlExtension:" << value);
        return false;
    }    
    return true;
}

blocxx::StringArray
NsRenewalUrlExtension::dump() const
{
    StringArray result;
    result.append("NsRenewalUrlExtension::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    result.append("URL = " + value);

    return result;
}

//    private:
NsRenewalUrlExtension::NsRenewalUrlExtension()
    : StringExtension(String())
{}

// #################################################################

NsCaPolicyUrlExtension::NsCaPolicyUrlExtension(const String &v)
    : StringExtension(v)
{
    if(!initURICheck().isValid(v)) {
        LOGIT_ERROR("invalid value for NsCaPolicyUrlExtension");
        BLOCXX_THROW(limal::ValueException, "invalid value for NsCaPolicyUrlExtension");
    }
    setPresent(true);
}

NsCaPolicyUrlExtension::NsCaPolicyUrlExtension(CA& ca, Type type)
    : StringExtension(String())
{
    // These types are not supported by this object
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = ca.getConfig()->exists(type2Section(type, true), "nsCaPolicyUrl");
    if(p) {
        StringArray   sp   = PerlRegEx("\\s*,\\s*")
            .split(ca.getConfig()->getValue(type2Section(type, true), "nsCaPolicyUrl"));
        if(sp[0].equalsIgnoreCase("critical")) {
            setCritical(true); 
            value = sp[1];
        } else {
            value = sp[0];
        }
    }
    setPresent(p);
}

NsCaPolicyUrlExtension::NsCaPolicyUrlExtension(const NsCaPolicyUrlExtension &extension)
    : StringExtension(extension)
{}

NsCaPolicyUrlExtension::~NsCaPolicyUrlExtension()
{}

NsCaPolicyUrlExtension&
NsCaPolicyUrlExtension::operator=(const NsCaPolicyUrlExtension& extension)
{
    if(this == &extension) return *this;

    StringExtension::operator=(extension);

    return *this;
}

void
NsCaPolicyUrlExtension::setValue(const String &v)
{
    if(!initURICheck().isValid(v)) {
        LOGIT_ERROR("invalid value for NsCaPolicyUrlExtension");
        BLOCXX_THROW(limal::ValueException, "invalid value for NsCaPolicyUrlExtension");
    }
    value = v;
    setPresent(true);
}

blocxx::String
NsCaPolicyUrlExtension::getValue() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "NsCaPolicyUrlExtension is not present");
    }
    return value;
}

void
NsCaPolicyUrlExtension::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid NsCaPolicyUrlExtension object");
        BLOCXX_THROW(limal::ValueException, "invalid NsCaPolicyUrlExtension object");
    }

    // This extension is not supported by type CRL
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent()) {
        String extString;

        if(isCritical()) extString += "critical,";
        extString += value;

        ca.getConfig()->setValue(type2Section(type, true), "nsCaPolicyUrl", extString);
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "nsCaPolicyUrl");
    }
}

blocxx::StringArray
NsCaPolicyUrlExtension::verify() const
{
    StringArray result;

    if(!isPresent()) return result;

    if(!initURICheck().isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsCaPolicyUrlExtension:" << value);
        result.append(Format("Wrong value for NsCaPolicyUrlExtension: %1", value).toString());
    }
    return result;
}

bool
NsCaPolicyUrlExtension::valid() const
{
    if(!isPresent()) return true;

    if(!initURICheck().isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsCaPolicyUrlExtension:" << value);
        return false;
    }    
    return true;
}

blocxx::StringArray
NsCaPolicyUrlExtension::dump() const
{
    StringArray result;
    result.append("NsCaPolicyUrlExtension::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    result.append("URL = " + value);

    return result;
}

//    private:
NsCaPolicyUrlExtension::NsCaPolicyUrlExtension()
    : StringExtension(String())
{}


// #################################################################

NsSslServerNameExtension::NsSslServerNameExtension(const String &v)
    : StringExtension(v)
{
    setPresent(true);
}

NsSslServerNameExtension::NsSslServerNameExtension(CA& ca, Type type)
    : StringExtension(String())
{
    // These types are not supported by this object
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = ca.getConfig()->exists(type2Section(type, true), "nsSslServerName");
    if(p) {
        StringArray   sp   = PerlRegEx("\\s*,\\s*")
            .split(ca.getConfig()->getValue(type2Section(type, true), "nsSslServerName"));
        if(sp[0].equalsIgnoreCase("critical")) {
            setCritical(true); 
            value = sp[1];
        } else {
            value = sp[0];
        }
    }
    setPresent(p);
}

NsSslServerNameExtension::NsSslServerNameExtension(const NsSslServerNameExtension &extension)
    : StringExtension(extension)
{}

NsSslServerNameExtension::~NsSslServerNameExtension()
{}

NsSslServerNameExtension&
NsSslServerNameExtension::operator=(const NsSslServerNameExtension& extension)
{
    if(this == &extension) return *this;

    StringExtension::operator=(extension);

    return *this;
}

void
NsSslServerNameExtension::setValue(const String &v)
{
    value = v;
    setPresent(true);
}

blocxx::String
NsSslServerNameExtension::getValue() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "NsSslServerNameExtension is not present");
    }
    return value;
}

void
NsSslServerNameExtension::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid NsSslServerNameExtension object");
        BLOCXX_THROW(limal::ValueException, "invalid NsSslServerNameExtension object");
    }

    // This extension is not supported by type CRL
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent()) {
        String extString;

        if(isCritical()) extString += "critical,";
        extString += value;

        ca.getConfig()->setValue(type2Section(type, true), "nsSslServerName", extString);
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "nsSslServerName");
    }
}

blocxx::StringArray
NsSslServerNameExtension::verify() const
{
    return blocxx::StringArray();
}

bool
NsSslServerNameExtension::valid() const
{
    return true;
}

blocxx::StringArray
NsSslServerNameExtension::dump() const
{
    StringArray result;
    result.append("NsSslServerNameExtension::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    result.append("SSL server name = " + value);

    return result;
}

//    private:

NsSslServerNameExtension::NsSslServerNameExtension()
    : StringExtension(String())
{}

// #################################################################

NsCommentExtension::NsCommentExtension(const String &v)
    : StringExtension(v)
{
    setPresent(true);
}

NsCommentExtension::NsCommentExtension(CA& ca, Type type)
    : StringExtension(String())
{
    // These types are not supported by this object
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = ca.getConfig()->exists(type2Section(type, true), "nsComment");
    if(p) {
        StringArray   sp   = PerlRegEx("\\s*,\\s*")
            .split(ca.getConfig()->getValue(type2Section(type, true), "nsComment"));
        if(sp[0].equalsIgnoreCase("critical")) {
            setCritical(true); 
            value = sp[1];
        } else {
            value = sp[0];
        }
    }
    setPresent(p);
}

NsCommentExtension::NsCommentExtension(const NsCommentExtension &extension)
    : StringExtension(extension)
{}

NsCommentExtension::~NsCommentExtension()
{}

NsCommentExtension&
NsCommentExtension::operator=(const NsCommentExtension& extension)
{
    if(this == &extension) return *this;

    StringExtension::operator=(extension);

    return *this;
}

void
NsCommentExtension::setValue(const String &v)
{
    value = v;
    setPresent(true);
}

blocxx::String
NsCommentExtension::getValue() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "NsCommentExtension is not present");
    }
    return value;
}

void
NsCommentExtension::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid NsCommentExtension object");
        BLOCXX_THROW(limal::ValueException, "invalid NsCommentExtension object");
    }

    // This extension is not supported by type CRL
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent()) {
        String extString;

        if(isCritical()) extString += "critical,";
        extString += value;

        ca.getConfig()->setValue(type2Section(type, true), "nsComment", extString);
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "nsComment");
    }
}

blocxx::StringArray
NsCommentExtension::verify() const
{
    return blocxx::StringArray();
}

bool
NsCommentExtension::valid() const
{
    return true;
}

blocxx::StringArray
NsCommentExtension::dump() const
{
    StringArray result;
    result.append("NsCommentExtension::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    result.append("NS Comment = " + value);

    return result;
}

//    private:
NsCommentExtension::NsCommentExtension()
    : StringExtension(String())
{}
