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

  File:       BitExtensions.cpp

  Author:     <Michael Calmer>     <mc@suse.de>
  Maintainer: <Michael Calmer>     <mc@suse.de>

  Purpose:

/-*/
#include  <limal/ca-mgm/BitExtensions.hpp>
#include  <limal/ca-mgm/CA.hpp>
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

#include "Utils.hpp"

namespace LIMAL_NAMESPACE
{
namespace CA_MGM_NAMESPACE
{

using namespace limal;
using namespace blocxx;

BitExtension::BitExtension()
    : ExtensionBase(), value(0)
{}

BitExtension::BitExtension(blocxx::UInt32 value)
    : ExtensionBase(), value(value)
{}

BitExtension::BitExtension(const BitExtension& extension)
    : ExtensionBase(extension), value(extension.value)
{}

BitExtension::~BitExtension()
{}

BitExtension&
BitExtension::operator=(const BitExtension& extension)
{
    if(this == &extension) return *this;

    ExtensionBase::operator=(extension);
    value = extension.value;

    return *this;
}

void
BitExtension::setValue(blocxx::UInt32 value)
{
    this->value = value;
    setPresent(true);   // ??
}

blocxx::UInt32
BitExtension::getValue() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "This BitExtension is not present");
    }
    return value;
}


// ###################################################################

       
KeyUsageExtension::KeyUsageExtension()
    : BitExtension()
{}

KeyUsageExtension::KeyUsageExtension(CAConfig* caConfig, Type type)
    : BitExtension()
{
    LOGIT_DEBUG("Parse KeyUsage");

    // These types are not supported by this object
    if(type == E_CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = caConfig->exists(type2Section(type, true), "keyUsage");
    if(p) {
        blocxx::UInt32 keyUsage = 0;
        
        String ku = caConfig->getValue(type2Section(type, true), "keyUsage");
        StringArray sp = PerlRegEx("\\s*,\\s*").split(ku);

        if(sp[0].equalsIgnoreCase("critical")) setCritical(true);

        StringArray::const_iterator it = sp.begin();
        for(; it != sp.end(); ++it) {
            if((*it).equalsIgnoreCase("digitalSignature"))      keyUsage |= digitalSignature; 
            else if((*it).equalsIgnoreCase("nonRepudiation"))   keyUsage |= nonRepudiation; 
            else if((*it).equalsIgnoreCase("keyEncipherment"))  keyUsage |= keyEncipherment; 
            else if((*it).equalsIgnoreCase("dataEncipherment")) keyUsage |= dataEncipherment; 
            else if((*it).equalsIgnoreCase("keyAgreement"))     keyUsage |= keyAgreement; 
            else if((*it).equalsIgnoreCase("keyCertSign"))      keyUsage |= keyCertSign; 
            else if((*it).equalsIgnoreCase("cRLSign"))          keyUsage |= cRLSign; 
            else if((*it).equalsIgnoreCase("encipherOnly"))     keyUsage |= encipherOnly; 
            else if((*it).equalsIgnoreCase("decipherOnly"))     keyUsage |= decipherOnly; 
            else
                LOGIT_INFO("Unknown KeyUsage option: " << (*it));

        }
        setKeyUsage(keyUsage);
    }
    setPresent(p);
}

KeyUsageExtension::KeyUsageExtension(blocxx::UInt32 keyUsage)
    : BitExtension(keyUsage)
{
    if(!validKeyUsage(value)) {
        BLOCXX_THROW(limal::ValueException, "invalid value for keyUsage");
    }
    setPresent(true);
}

KeyUsageExtension::KeyUsageExtension(const KeyUsageExtension& extension)
    : BitExtension(extension)
{}

KeyUsageExtension::~KeyUsageExtension()
{}


KeyUsageExtension&
KeyUsageExtension::operator=(const KeyUsageExtension& extension)
{
    if(this == &extension) return *this;

    BitExtension::operator=(extension);

    return *this;
}

void
KeyUsageExtension::setKeyUsage(blocxx::UInt32 keyUsage)
{
    if(!validKeyUsage(keyUsage)) {
        BLOCXX_THROW(limal::ValueException, "invalid value for keyUsage");
    }
    setValue(keyUsage);
    setPresent(true);
}

blocxx::UInt32
KeyUsageExtension::getKeyUsage() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "KeyUsageExtension is not present");
    }
    return value;
}

bool
KeyUsageExtension::isEnabledFor(KeyUsage ku) const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "KeyUsageExtension is not present");
    }
    
    return !!(value & ku);
}

void
KeyUsageExtension::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid KeyUsageExtension object");
        BLOCXX_THROW(limal::ValueException, "invalid KeyUsageExtension object");
    }

    // This extension is not supported by type CRL
    if(type == E_CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent()) {
        String keyUsageString;

        if(isCritical()) keyUsageString += "critical,";

        if(!!(value & KeyUsageExtension::digitalSignature)) {
            keyUsageString += "digitalSignature,";
        }
        if(!!(value & KeyUsageExtension::nonRepudiation)) {
            keyUsageString += "nonRepudiation,";
        }
        if(!!(value & KeyUsageExtension::keyEncipherment)) {
            keyUsageString += "keyEncipherment,";
        }
        if(!!(value & KeyUsageExtension::dataEncipherment)) {
            keyUsageString += "dataEncipherment,";
        }
        if(!!(value & KeyUsageExtension::keyAgreement)) {
            keyUsageString += "keyAgreement,";
        }
        if(!!(value & KeyUsageExtension::keyCertSign)) {
            keyUsageString += "keyCertSign,";
        }
        if(!!(value & KeyUsageExtension::cRLSign)) {
            keyUsageString += "cRLSign,";
        }
        if(!!(value & KeyUsageExtension::encipherOnly)) {
            keyUsageString += "encipherOnly,";
        }
        if(!!(value & KeyUsageExtension::decipherOnly)) {
            keyUsageString += "decipherOnly,";
        }
        
        ca.getConfig()->setValue(type2Section(type, true), "keyUsage", 
                                 keyUsageString.erase(keyUsageString.length()-1));
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "keyUsage");
    }
}

bool
KeyUsageExtension::valid() const
{
    if(!isPresent()) return true;

    if(!validKeyUsage(value)) return false;
    
    return true;
}

blocxx::StringArray
KeyUsageExtension::verify() const
{
    blocxx::StringArray result;

    if(!isPresent()) return result;

    if(!validKeyUsage(value)) {
        result.append(Format("invalid value '%1' for keyUsage", value).toString());
    }

    LOGIT_DEBUG_STRINGARRAY("KeyUsageExtension::verify()", result);
    return result;
}

blocxx::StringArray
KeyUsageExtension::dump() const
{
    StringArray result;
    result.append("KeyUsageExtension::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    String ku;
    ku.format("%04x", value);
    result.append("KeyUsage = 0x" + ku);

    return result;
}


bool
KeyUsageExtension::validKeyUsage(blocxx::UInt32 keyUsage) const
{
    UInt32 mask = 0x80FF;
    if( (keyUsage&mask) != keyUsage || keyUsage == 0) {
        return false;
    }
    return true;
}


// ###################################################################

        
NsCertTypeExtension::NsCertTypeExtension()
    : BitExtension()
{}

NsCertTypeExtension::NsCertTypeExtension(CAConfig* caConfig, Type type)
    : BitExtension()
{
    LOGIT_DEBUG("Parse NsCertType");

    // These types are not supported by this object
    if(type == E_CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = caConfig->exists(type2Section(type, true), "nsCertType");
    if(p) {
        blocxx::UInt32 bits = 0;
        
        String ct = caConfig->getValue(type2Section(type, true), "nsCertType");
        StringArray sp = PerlRegEx("\\s*,\\s*").split(ct);

        if(sp[0].equalsIgnoreCase("critical")) setCritical(true);

        StringArray::const_iterator it = sp.begin();
        for(; it != sp.end(); ++it) {
            if((*it).equalsIgnoreCase("client"))        bits |= client; 
            else if((*it).equalsIgnoreCase("server"))   bits |= server; 
            else if((*it).equalsIgnoreCase("email"))    bits |= email; 
            else if((*it).equalsIgnoreCase("objsign"))  bits |= objsign; 
            else if((*it).equalsIgnoreCase("reserved")) bits |= reserved; 
            else if((*it).equalsIgnoreCase("sslCA"))    bits |= sslCA; 
            else if((*it).equalsIgnoreCase("emailCA"))  bits |= emailCA; 
            else if((*it).equalsIgnoreCase("objCA"))    bits |= objCA;
            else
                LOGIT_INFO("Unknown NsCertType option: " << (*it));
        }
        setNsCertType(bits);
    }
    setPresent(p);
}

NsCertTypeExtension::NsCertTypeExtension(blocxx::UInt32 nsCertTypes)
    : BitExtension(nsCertTypes)
{
    if(value > 0xFF || value == 0) {
        BLOCXX_THROW(limal::ValueException, "invalid value for NsCertTypeExtension");
    }
    setPresent(true);
}

NsCertTypeExtension::NsCertTypeExtension(const NsCertTypeExtension& extension)
    : BitExtension(extension)
{}

NsCertTypeExtension::~NsCertTypeExtension()
{}


NsCertTypeExtension&
NsCertTypeExtension::operator=(const NsCertTypeExtension& extension)
{
    if(this == &extension) return *this;

    BitExtension::operator=(extension);

    return *this;
}

void
NsCertTypeExtension::setNsCertType(blocxx::UInt32 nsCertTypes)
{
    if(nsCertTypes > 0xFF || nsCertTypes == 0) {
        BLOCXX_THROW(limal::ValueException, 
                     Format("invalid value for NsCertTypeExtension: %1", nsCertTypes).c_str());
    }
    setValue(nsCertTypes);
    setPresent(true);
}

blocxx::UInt32
NsCertTypeExtension::getNsCertType() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "NsCertTypeExtension is not present");
    }
    return value;
}

bool
NsCertTypeExtension::isEnabledFor(NsCertType nsCertType) const
{
    // if ! isPresent() ... throw exceptions?
    if(!isPresent()) return false;

    return !!(value & nsCertType);
}

void
NsCertTypeExtension::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid NsCertTypeExtension object");
        BLOCXX_THROW(limal::ValueException, "invalid NsCertTypeExtension object");
    }

    // This extension is not supported by type CRL
    if(type == E_CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent()) {
        String nsCertTypeString;

        if(isCritical()) nsCertTypeString += "critical,";

        if(!!(value & NsCertTypeExtension::client)) {
            nsCertTypeString += "client,";
        }
        if(!!(value & NsCertTypeExtension::server)) {
            nsCertTypeString += "server,";
        }
        if(!!(value & NsCertTypeExtension::email)) {
            nsCertTypeString += "email,";
        }
        if(!!(value & NsCertTypeExtension::objsign)) {
            nsCertTypeString += "objsign,";
        }
        if(!!(value & NsCertTypeExtension::reserved)) {
            nsCertTypeString += "reserved,";
        }
        if(!!(value & NsCertTypeExtension::sslCA)) {
            nsCertTypeString += "sslCA,";
        }
        if(!!(value & NsCertTypeExtension::emailCA)) {
            nsCertTypeString += "emailCA,";
        }
        if(!!(value & NsCertTypeExtension::objCA)) {
            nsCertTypeString += "objCA,";
        }
        
        ca.getConfig()->setValue(type2Section(type, true), "nsCertType", 
                                 nsCertTypeString.erase(nsCertTypeString.length()-1));
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "nsCertType");
    }
}

bool
NsCertTypeExtension::valid() const
{
    if(!isPresent()) return true;

    if(value > 0xFF || value == 0) return false;
    
    return true;
}

blocxx::StringArray
NsCertTypeExtension::verify() const
{
    blocxx::StringArray result;

    if(!isPresent()) return result;

    if(value > 0xFF || value == 0) {
        result.append(Format("invalid value '%1' for nsCertType", value).toString());
    }
    LOGIT_DEBUG_STRINGARRAY("NsCertTypeExtension::verify()", result);
    return result;
}

blocxx::StringArray
NsCertTypeExtension::dump() const
{
    StringArray result;
    result.append("NsCertTypeExtension::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    String nsct;
    nsct.format("%02x", value);
    result.append("NsCertType = 0x" + nsct);

    return result;
}

}
}

