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
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

#include  "Utils.hpp"

using namespace limal;
using namespace limal::ca_mgm;
using namespace blocxx;

inline static ValueCheck initURLCheck() {
    ValueCheck checkURI =
        ValueCheck(new ValuePosixRECheck("^(([^:/?#]+)://)?([^/?#]*)?([^?#]*)?(\\\\?([^#]*))?(#(.*))?"  ));

    return checkURI;
}
    
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
    if(!this->valid()) {
        BLOCXX_THROW(limal::ValueException, "invalid value for NsBaseUrlExtension");
    }
    setPresent(true);
}

NsBaseUrlExtension::NsBaseUrlExtension(CA& ca, Type type)
    : StringExtension(String())
{}

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
    String oldValue = value;

    value = v;

    StringArray r = this->verify();
    if(!r.empty()) {
        value = oldValue;
        
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
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
NsBaseUrlExtension::commit2Config(CA& ca, Type type)
{
}

bool
NsBaseUrlExtension::valid() const
{
    if(!isPresent()) return true;

    ValueCheck check = initURLCheck();
    if(!check.isValid(value)) {
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

    ValueCheck check = initURLCheck();
    if(!check.isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsBaseUrlExtension:" << value);
        result.append(Format("Wrong value for NsBaseUrlExtension: %1", value).toString());
    }
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
    if(!this->valid()) {
        BLOCXX_THROW(limal::ValueException, "invalid value for NsRevocationUrlExtension");
    }
    setPresent(true);
}

NsRevocationUrlExtension::NsRevocationUrlExtension(CA& ca, Type type)
    : StringExtension(String())
{}

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
    String oldValue = value;
    
    value = v;
    
    StringArray r = this->verify();
    if(!r.empty()) {
        value = oldValue;
        
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
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
NsRevocationUrlExtension::commit2Config(CA& ca, Type type)
{
}

blocxx::StringArray
NsRevocationUrlExtension::verify() const
{
    StringArray result;

    if(!isPresent()) return result;

    ValueCheck check = initURLCheck();
    if(!check.isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsRevocationUrlExtension:" << value);
        result.append(Format("Wrong value for NsRevocationUrlExtension: %1", value).toString());
    }
    return result;
}

bool
NsRevocationUrlExtension::valid() const
{
    if(!isPresent()) return true;

    ValueCheck check = initURLCheck();
    if(!check.isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsRevocationUrlExtension:" << value);
        return false;
    }    
    return true;
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
    if(!this->valid()) {
        BLOCXX_THROW(limal::ValueException, "invalid value for NsCaRevocationUrlExtension");
    }
    setPresent(true);
}

NsCaRevocationUrlExtension::NsCaRevocationUrlExtension(CA& ca, Type type)
    : StringExtension(String())
{}

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
    String oldValue = value;
    
    value = v;
    
    StringArray r = this->verify();
    if(!r.empty()) {
        value = oldValue;
        
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
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
NsCaRevocationUrlExtension::commit2Config(CA& ca, Type type)
{
}

blocxx::StringArray
NsCaRevocationUrlExtension::verify() const
{
    StringArray result;

    if(!isPresent()) return result;

    ValueCheck check = initURLCheck();
    if(!check.isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsCaRevocationUrlExtension:" << value);
        result.append(Format("Wrong value for NsCaRevocationUrlExtension: %1", value).toString());
    }
    return result;
}

bool
NsCaRevocationUrlExtension::valid() const
{
    if(!isPresent()) return true;

    ValueCheck check = initURLCheck();
    if(!check.isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsCaRevocationUrlExtension:" << value);
        return false;
    }    
    return true;
}

//  private:
NsCaRevocationUrlExtension::NsCaRevocationUrlExtension()
    : StringExtension(String())
{}


// #################################################################

NsRenewalUrlExtension::NsRenewalUrlExtension(const String &v)
    : StringExtension(v)
{
    if(!this->valid()) {
        BLOCXX_THROW(limal::ValueException, "invalid value for NsRenewalUrlExtension");
    }
    setPresent(true);
}

NsRenewalUrlExtension::NsRenewalUrlExtension(CA& ca, Type type)
    : StringExtension(String())
{}

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
    String oldValue = value;
    
    value = v;
    
    StringArray r = this->verify();
    if(!r.empty()) {
        value = oldValue;
        
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
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
NsRenewalUrlExtension::commit2Config(CA& ca, Type type)
{
}

blocxx::StringArray
NsRenewalUrlExtension::verify() const
{
    StringArray result;

    if(!isPresent()) return result;

    ValueCheck check = initURLCheck();
    if(!check.isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsRenewalUrlExtension:" << value);
        result.append(Format("Wrong value for NsRenewalUrlExtension: %1", value).toString());
    }
    return result;
}

bool
NsRenewalUrlExtension::valid() const
{
    if(!isPresent()) return true;

    ValueCheck check = initURLCheck();
    if(!check.isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsRenewalUrlExtension:" << value);
        return false;
    }    
    return true;
}


//    private:
NsRenewalUrlExtension::NsRenewalUrlExtension()
    : StringExtension(String())
{}

// #################################################################

NsCaPolicyUrlExtension::NsCaPolicyUrlExtension(const String &v)
    : StringExtension(v)
{
    if(!this->valid()) {
        BLOCXX_THROW(limal::ValueException, "invalid value for NsCaPolicyUrlExtension");
    }
    setPresent(true);
}

NsCaPolicyUrlExtension::NsCaPolicyUrlExtension(CA& ca, Type type)
    : StringExtension(String())
{}

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
    String oldValue = value;
    
    value = v;
    
    StringArray r = this->verify();
    if(!r.empty()) {
        value = oldValue;
        
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
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
NsCaPolicyUrlExtension::commit2Config(CA& ca, Type type)
{
}

blocxx::StringArray
NsCaPolicyUrlExtension::verify() const
{
    StringArray result;

    if(!isPresent()) return result;

    ValueCheck check = initURLCheck();
    if(!check.isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsCaPolicyUrlExtension:" << value);
        result.append(Format("Wrong value for NsCaPolicyUrlExtension: %1", value).toString());
    }
    return result;
}

bool
NsCaPolicyUrlExtension::valid() const
{
    if(!isPresent()) return true;

    ValueCheck check = initURLCheck();
    if(!check.isValid(value)) {
        LOGIT_DEBUG("Wrong value for NsCaPolicyUrlExtension:" << value);
        return false;
    }    
    return true;
}

//    private:
NsCaPolicyUrlExtension::NsCaPolicyUrlExtension()
    : StringExtension(String())
{}


// #################################################################

NsSslServerNameExtension::NsSslServerNameExtension(const String &v)
    : StringExtension(v)
{
    if(!this->valid()) {
        BLOCXX_THROW(limal::ValueException, "invalid value for NsSslServerNameExtension");
    }
    setPresent(true);
}

NsSslServerNameExtension::NsSslServerNameExtension(CA& ca, Type type)
    : StringExtension(String())
{}

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
    String oldValue = value;
    
    value = v;
    
    StringArray r = this->verify();
    if(!r.empty()) {
        value = oldValue;
        
        LOGIT_ERROR(r[0]);
        BLOCXX_THROW(limal::ValueException, r[0].c_str());
    }
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
NsSslServerNameExtension::commit2Config(CA& ca, Type type)
{
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
{}

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
NsCommentExtension::commit2Config(CA& ca, Type type)
{
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

//    private:
NsCommentExtension::NsCommentExtension()
    : StringExtension(String())
{}
