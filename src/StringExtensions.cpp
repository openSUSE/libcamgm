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

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
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

NsBaseUrlExt::NsBaseUrlExt(const String &v)
    : StringExtension(v)
{
    if(!initURICheck().isValid(v)) {
        LOGIT_ERROR("invalid value for NsBaseUrlExt");
        BLOCXX_THROW(limal::ValueException, "invalid value for NsBaseUrlExt");
    }
    setPresent(true);
}

NsBaseUrlExt::NsBaseUrlExt(CAConfig* caConfig, Type type)
    : StringExtension(String())
{
    // These types are not supported by this object
    if(type == E_CRL)
    {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = caConfig->exists(type2Section(type, true), "nsBaseUrl");
    if(p) {
        StringArray   sp   = PerlRegEx("\\s*,\\s*")
            .split(caConfig->getValue(type2Section(type, true), "nsBaseUrl"));
        if(sp[0].equalsIgnoreCase("critical")) {
            setCritical(true); 
            value = sp[1];
        } else {
            value = sp[0];
        }
    }
    setPresent(p);
}

NsBaseUrlExt::NsBaseUrlExt(const NsBaseUrlExt &extension)
    : StringExtension(extension)
{}

NsBaseUrlExt::~NsBaseUrlExt()
{}

NsBaseUrlExt&
NsBaseUrlExt::operator=(const NsBaseUrlExt& extension)
{
    if(this == &extension) return *this;

    StringExtension::operator=(extension);

    return *this;
}

void
NsBaseUrlExt::setValue(const String &v)
{
    if(!initURICheck().isValid(v)) {
        LOGIT_ERROR("invalid value for NsBaseUrlExt");
        BLOCXX_THROW(limal::ValueException, "invalid value for NsBaseUrlExt");
    }
    value = v;
    setPresent(true);
}

blocxx::String
NsBaseUrlExt::getValue() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "NsBaseUrlExt is not present");
    }
    return value;
}

void
NsBaseUrlExt::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid NsBaseUrlExt object");
        BLOCXX_THROW(limal::ValueException, "invalid NsBaseUrlExt object");
    }

    // This extension is not supported by type CRL
    if(type == E_CRL) {
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
NsBaseUrlExt::valid() const
{
    if(!isPresent()) return true;

    if(!initURICheck().isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsBaseUrlExt:" << value);
        return false;
    }    
    return true;
}

blocxx::StringArray
NsBaseUrlExt::verify() const
{
    StringArray result;

    if(!isPresent()) return result;

    if(!initURICheck().isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsBaseUrlExt:" << value);
        result.append(Format("Wrong value for NsBaseUrlExt: %1", value).toString());
    }
    LOGIT_DEBUG_STRINGARRAY("NsBaseUrlExt::verify()", result);
    return result;
}

blocxx::StringArray
NsBaseUrlExt::dump() const
{
    StringArray result;
    result.append("NsBaseUrlExt::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    result.append("URL = " + value);

    return result;
}


// private:
NsBaseUrlExt::NsBaseUrlExt()
    : StringExtension(String())
{}


// #################################################################

NsRevocationUrlExt::NsRevocationUrlExt(const String &v)
    : StringExtension(v)
{
    if(!initURICheck().isValid(v)) {
        LOGIT_ERROR("invalid value for NsRevocationUrlExt");
        BLOCXX_THROW(limal::ValueException, "invalid value for NsRevocationUrlExt");
    }
    setPresent(true);
}

NsRevocationUrlExt::NsRevocationUrlExt(CAConfig* caConfig, Type type)
    : StringExtension(String())
{
    // These types are not supported by this object
    if(type == E_CRL)
    {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }
    
    bool p = caConfig->exists(type2Section(type, true), "nsRevocationUrl");
    if(p) {
        StringArray   sp   = PerlRegEx("\\s*,\\s*")
            .split(caConfig->getValue(type2Section(type, true), "nsRevocationUrl"));
        if(sp[0].equalsIgnoreCase("critical")) {
            setCritical(true); 
            value = sp[1];
        } else {
            value = sp[0];
        }
    }
    setPresent(p);
}

NsRevocationUrlExt::NsRevocationUrlExt(const NsRevocationUrlExt &extension)
    : StringExtension(extension)
{}

NsRevocationUrlExt::~NsRevocationUrlExt()
{}

NsRevocationUrlExt&
NsRevocationUrlExt::operator=(const NsRevocationUrlExt& extension)
{
    if(this == &extension) return *this;

    StringExtension::operator=(extension);

    return *this;
}

void
NsRevocationUrlExt::setValue(const String &v)
{
    if(!initURICheck().isValid(v)) {
        LOGIT_ERROR("invalid value for NsRevocationUrlExt");
        BLOCXX_THROW(limal::ValueException, "invalid value for NsRevocationUrlExt");
    }
    value = v;
    setPresent(true);
}

blocxx::String
NsRevocationUrlExt::getValue() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "NsRevocationUrlExt is not present");
    }
    return value;
}

void
NsRevocationUrlExt::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid NsRevocationUrlExt object");
        BLOCXX_THROW(limal::ValueException, "invalid NsRevocationUrlExt object");
    }

    // This extension is not supported by type CRL
    if(type == E_CRL)
    {
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
NsRevocationUrlExt::verify() const
{
    StringArray result;

    if(!isPresent()) return result;

    if(!initURICheck().isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsRevocationUrlExt:" << value);
        result.append(Format("Wrong value for NsRevocationUrlExt: %1", value).toString());
    }
    LOGIT_DEBUG_STRINGARRAY("NsRevocationUrlExt::verify()", result);
    return result;
}

bool
NsRevocationUrlExt::valid() const
{
    if(!isPresent()) return true;

    if(!initURICheck().isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsRevocationUrlExt:" << value);
        return false;
    }    
    return true;
}

blocxx::StringArray
NsRevocationUrlExt::dump() const
{
    StringArray result;
    result.append("NsRevocationUrlExt::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    result.append("URL = " + value);

    return result;
}

//    private:
NsRevocationUrlExt::NsRevocationUrlExt()
    : StringExtension(String())
{
}


// #################################################################

NsCaRevocationUrlExt::NsCaRevocationUrlExt(const String &v)
    : StringExtension(v)
{
    if(!initURICheck().isValid(v)) {
        LOGIT_ERROR("invalid value for NsCaRevocationUrlExt");
        BLOCXX_THROW(limal::ValueException, "invalid value for NsCaRevocationUrlExt");
    }
    setPresent(true);
}

NsCaRevocationUrlExt::NsCaRevocationUrlExt(CAConfig* caConfig, Type type)
    : StringExtension(String())
{
    // These types are not supported by this object
    if(type == E_CRL)
    {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = caConfig->exists(type2Section(type, true), "nsCaRevocationUrl");
    if(p) {
        StringArray   sp   = PerlRegEx("\\s*,\\s*")
            .split(caConfig->getValue(type2Section(type, true), "nsCaRevocationUrl"));
        if(sp[0].equalsIgnoreCase("critical")) {
            setCritical(true); 
            value = sp[1];
        } else {
            value = sp[0];
        }
    }
    setPresent(p);
}

NsCaRevocationUrlExt::NsCaRevocationUrlExt(const NsCaRevocationUrlExt &extension)
    : StringExtension(extension)
{}

NsCaRevocationUrlExt::~NsCaRevocationUrlExt()
{}

NsCaRevocationUrlExt&
NsCaRevocationUrlExt::operator=(const NsCaRevocationUrlExt& extension)
{
    if(this == &extension) return *this;

    StringExtension::operator=(extension);

    return *this;
}

void
NsCaRevocationUrlExt::setValue(const String &v)
{
    if(!initURICheck().isValid(v)) {
        LOGIT_ERROR("invalid value for NsCaRevocationUrlExt");
        BLOCXX_THROW(limal::ValueException, "invalid value for NsCaRevocationUrlExt");
    }
    value = v;
    setPresent(true);
}

blocxx::String
NsCaRevocationUrlExt::getValue() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "NsCaRevocationUrlExt is not present");
    }
    return value;
}

void
NsCaRevocationUrlExt::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid NsCaRevocationUrlExt object");
        BLOCXX_THROW(limal::ValueException, "invalid NsCaRevocationUrlExt object");
    }

    // This extension is not supported by type CRL
    if(type == E_CRL)
    {
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
NsCaRevocationUrlExt::verify() const
{
    StringArray result;

    if(!isPresent()) return result;

    if(!initURICheck().isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsCaRevocationUrlExt:" << value);
        result.append(Format("Wrong value for NsCaRevocationUrlExt: %1", value).toString());
    }
    LOGIT_DEBUG_STRINGARRAY("NsCaRevocationUrlExt::verify()", result);
    return result;
}

bool
NsCaRevocationUrlExt::valid() const
{
    if(!isPresent()) return true;

    if(!initURICheck().isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsCaRevocationUrlExt:" << value);
        return false;
    }    
    return true;
}

blocxx::StringArray
NsCaRevocationUrlExt::dump() const
{
    StringArray result;
    result.append("NsCaRevocationUrlExt::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    result.append("URL = " + value);

    return result;
}

//  private:
NsCaRevocationUrlExt::NsCaRevocationUrlExt()
    : StringExtension(String())
{}


// #################################################################

NsRenewalUrlExt::NsRenewalUrlExt(const String &v)
    : StringExtension(v)
{
    if(!initURICheck().isValid(v)) {
        LOGIT_ERROR("invalid value for NsRenewalUrlExt");
        BLOCXX_THROW(limal::ValueException, "invalid value for NsRenewalUrlExt");
    }
    setPresent(true);
}

NsRenewalUrlExt::NsRenewalUrlExt(CAConfig* caConfig, Type type)
    : StringExtension(String())
{
    // These types are not supported by this object
    if(type == E_CRL)
    {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = caConfig->exists(type2Section(type, true), "nsRenewalUrl");
    if(p) {
        StringArray   sp   = PerlRegEx("\\s*,\\s*")
            .split(caConfig->getValue(type2Section(type, true), "nsRenewalUrl"));
        if(sp[0].equalsIgnoreCase("critical")) {
            setCritical(true); 
            value = sp[1];
        } else {
            value = sp[0];
        }
    }
    setPresent(p);
}

NsRenewalUrlExt::NsRenewalUrlExt(const NsRenewalUrlExt &extension)
    : StringExtension(extension)
{}

NsRenewalUrlExt::~NsRenewalUrlExt()
{}

NsRenewalUrlExt&
NsRenewalUrlExt::operator=(const NsRenewalUrlExt& extension)
{
    if(this == &extension) return *this;

    StringExtension::operator=(extension);

    return *this;
}

void
NsRenewalUrlExt::setValue(const String &v)
{
    if(!initURICheck().isValid(v)) {
        LOGIT_ERROR("invalid value for NsRenewalUrlExt");
        BLOCXX_THROW(limal::ValueException, "invalid value for NsRenewalUrlExt");
    }
    value = v;
    setPresent(true);
}

blocxx::String
NsRenewalUrlExt::getValue() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "NsRenewalUrlExt is not present");
    }
    return value;
}

void
NsRenewalUrlExt::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid NsRenewalUrlExt object");
        BLOCXX_THROW(limal::ValueException, "invalid NsRenewalUrlExt object");
    }

    // This extension is not supported by type CRL
    if(type == E_CRL)
    {
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
NsRenewalUrlExt::verify() const
{
    StringArray result;

    if(!isPresent()) return result;

    if(!initURICheck().isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsRenewalUrlExt:" << value);
        result.append(Format("Wrong value for NsRenewalUrlExt: %1", value).toString());
    }
    LOGIT_DEBUG_STRINGARRAY("NsRenewalUrlExt::verify()", result);
    return result;
}

bool
NsRenewalUrlExt::valid() const
{
    if(!isPresent()) return true;

    if(!initURICheck().isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsRenewalUrlExt:" << value);
        return false;
    }    
    return true;
}

blocxx::StringArray
NsRenewalUrlExt::dump() const
{
    StringArray result;
    result.append("NsRenewalUrlExt::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    result.append("URL = " + value);

    return result;
}

//    private:
NsRenewalUrlExt::NsRenewalUrlExt()
    : StringExtension(String())
{}

// #################################################################

NsCaPolicyUrlExt::NsCaPolicyUrlExt(const String &v)
    : StringExtension(v)
{
    if(!initURICheck().isValid(v)) {
        LOGIT_ERROR("invalid value for NsCaPolicyUrlExt");
        BLOCXX_THROW(limal::ValueException, "invalid value for NsCaPolicyUrlExt");
    }
    setPresent(true);
}

NsCaPolicyUrlExt::NsCaPolicyUrlExt(CAConfig* caConfig, Type type)
    : StringExtension(String())
{
    // These types are not supported by this object
    if(type == E_CRL)
    {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = caConfig->exists(type2Section(type, true), "nsCaPolicyUrl");
    if(p) {
        StringArray   sp   = PerlRegEx("\\s*,\\s*")
            .split(caConfig->getValue(type2Section(type, true), "nsCaPolicyUrl"));
        if(sp[0].equalsIgnoreCase("critical")) {
            setCritical(true); 
            value = sp[1];
        } else {
            value = sp[0];
        }
    }
    setPresent(p);
}

NsCaPolicyUrlExt::NsCaPolicyUrlExt(const NsCaPolicyUrlExt &extension)
    : StringExtension(extension)
{}

NsCaPolicyUrlExt::~NsCaPolicyUrlExt()
{}

NsCaPolicyUrlExt&
NsCaPolicyUrlExt::operator=(const NsCaPolicyUrlExt& extension)
{
    if(this == &extension) return *this;

    StringExtension::operator=(extension);

    return *this;
}

void
NsCaPolicyUrlExt::setValue(const String &v)
{
    if(!initURICheck().isValid(v)) {
        LOGIT_ERROR("invalid value for NsCaPolicyUrlExt");
        BLOCXX_THROW(limal::ValueException, "invalid value for NsCaPolicyUrlExt");
    }
    value = v;
    setPresent(true);
}

blocxx::String
NsCaPolicyUrlExt::getValue() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "NsCaPolicyUrlExt is not present");
    }
    return value;
}

void
NsCaPolicyUrlExt::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid NsCaPolicyUrlExt object");
        BLOCXX_THROW(limal::ValueException, "invalid NsCaPolicyUrlExt object");
    }

    // This extension is not supported by type CRL
    if(type == E_CRL)
    {
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
NsCaPolicyUrlExt::verify() const
{
    StringArray result;

    if(!isPresent()) return result;

    if(!initURICheck().isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsCaPolicyUrlExt:" << value);
        result.append(Format("Wrong value for NsCaPolicyUrlExt: %1", value).toString());
    }
    LOGIT_DEBUG_STRINGARRAY("NsCaPolicyUrlExt::verify()", result);
    return result;
}

bool
NsCaPolicyUrlExt::valid() const
{
    if(!isPresent()) return true;

    if(!initURICheck().isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsCaPolicyUrlExt:" << value);
        return false;
    }    
    return true;
}

blocxx::StringArray
NsCaPolicyUrlExt::dump() const
{
    StringArray result;
    result.append("NsCaPolicyUrlExt::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    result.append("URL = " + value);

    return result;
}

//    private:
NsCaPolicyUrlExt::NsCaPolicyUrlExt()
    : StringExtension(String())
{}


// #################################################################

NsSslServerNameExt::NsSslServerNameExt(const String &v)
    : StringExtension(v)
{
    setPresent(true);
}

NsSslServerNameExt::NsSslServerNameExt(CAConfig* caConfig, Type type)
    : StringExtension(String())
{
    // These types are not supported by this object
    if(type == E_CRL)
    {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = caConfig->exists(type2Section(type, true), "nsSslServerName");
    if(p) {
        StringArray   sp   = PerlRegEx("\\s*,\\s*")
            .split(caConfig->getValue(type2Section(type, true), "nsSslServerName"));
        if(sp[0].equalsIgnoreCase("critical")) {
            setCritical(true); 
            value = sp[1];
        } else {
            value = sp[0];
        }
    }
    setPresent(p);
}

NsSslServerNameExt::NsSslServerNameExt(const NsSslServerNameExt &extension)
    : StringExtension(extension)
{}

NsSslServerNameExt::~NsSslServerNameExt()
{}

NsSslServerNameExt&
NsSslServerNameExt::operator=(const NsSslServerNameExt& extension)
{
    if(this == &extension) return *this;

    StringExtension::operator=(extension);

    return *this;
}

void
NsSslServerNameExt::setValue(const String &v)
{
    value = v;
    setPresent(true);
}

blocxx::String
NsSslServerNameExt::getValue() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "NsSslServerNameExt is not present");
    }
    return value;
}

void
NsSslServerNameExt::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid NsSslServerNameExt object");
        BLOCXX_THROW(limal::ValueException, "invalid NsSslServerNameExt object");
    }

    // This extension is not supported by type CRL
    if(type == E_CRL) {
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
NsSslServerNameExt::verify() const
{
    return blocxx::StringArray();
}

bool
NsSslServerNameExt::valid() const
{
    return true;
}

blocxx::StringArray
NsSslServerNameExt::dump() const
{
    StringArray result;
    result.append("NsSslServerNameExt::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    result.append("SSL server name = " + value);

    return result;
}

//    private:

NsSslServerNameExt::NsSslServerNameExt()
    : StringExtension(String())
{}

// #################################################################

NsCommentExt::NsCommentExt(const String &v)
    : StringExtension(v)
{
    setPresent(true);
}

NsCommentExt::NsCommentExt(CAConfig* caConfig, Type type)
    : StringExtension(String())
{
    // These types are not supported by this object
    if(type == E_CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = caConfig->exists(type2Section(type, true), "nsComment");
    if(p) {
        StringArray   sp   = PerlRegEx("\\s*,\\s*")
            .split(caConfig->getValue(type2Section(type, true), "nsComment"));
        if(sp[0].equalsIgnoreCase("critical")) {
            setCritical(true); 
            value = sp[1];
        } else {
            value = sp[0];
        }
    }
    setPresent(p);
}

NsCommentExt::NsCommentExt(const NsCommentExt &extension)
    : StringExtension(extension)
{}

NsCommentExt::~NsCommentExt()
{}

NsCommentExt&
NsCommentExt::operator=(const NsCommentExt& extension)
{
    if(this == &extension) return *this;

    StringExtension::operator=(extension);

    return *this;
}

void
NsCommentExt::setValue(const String &v)
{
    value = v;
    setPresent(true);
}

blocxx::String
NsCommentExt::getValue() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "NsCommentExt is not present");
    }
    return value;
}

void
NsCommentExt::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid NsCommentExt object");
        BLOCXX_THROW(limal::ValueException, "invalid NsCommentExt object");
    }

    // This extension is not supported by type CRL
    if(type == E_CRL) {
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
NsCommentExt::verify() const
{
    return blocxx::StringArray();
}

bool
NsCommentExt::valid() const
{
    return true;
}

blocxx::StringArray
NsCommentExt::dump() const
{
    StringArray result;
    result.append("NsCommentExt::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    result.append("NS Comment = " + value);

    return result;
}

//    private:
NsCommentExt::NsCommentExt()
    : StringExtension(String())
{}

}
}
