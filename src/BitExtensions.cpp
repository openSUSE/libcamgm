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

       
KeyUsageExt::KeyUsageExt()
    : BitExtension()
{}

KeyUsageExt::KeyUsageExt(CAConfig* caConfig, Type type)
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

KeyUsageExt::KeyUsageExt(blocxx::UInt32 keyUsage)
    : BitExtension(keyUsage)
{
    if(!validKeyUsage(value)) {
        BLOCXX_THROW(limal::ValueException, "invalid value for keyUsage");
    }
    setPresent(true);
}

KeyUsageExt::KeyUsageExt(const KeyUsageExt& extension)
    : BitExtension(extension)
{}

KeyUsageExt::~KeyUsageExt()
{}


KeyUsageExt&
KeyUsageExt::operator=(const KeyUsageExt& extension)
{
    if(this == &extension) return *this;

    BitExtension::operator=(extension);

    return *this;
}

void
KeyUsageExt::setKeyUsage(blocxx::UInt32 keyUsage)
{
    if(!validKeyUsage(keyUsage)) {
        BLOCXX_THROW(limal::ValueException, "invalid value for keyUsage");
    }
    setValue(keyUsage);
    setPresent(true);
}

blocxx::UInt32
KeyUsageExt::getKeyUsage() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "KeyUsageExt is not present");
    }
    return value;
}

bool
KeyUsageExt::isEnabledFor(KeyUsage ku) const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "KeyUsageExt is not present");
    }
    
    return !!(value & ku);
}

void
KeyUsageExt::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid KeyUsageExt object");
        BLOCXX_THROW(limal::ValueException, "invalid KeyUsageExt object");
    }

    // This extension is not supported by type CRL
    if(type == E_CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent()) {
        String keyUsageString;

        if(isCritical()) keyUsageString += "critical,";

        if(!!(value & KeyUsageExt::digitalSignature)) {
            keyUsageString += "digitalSignature,";
        }
        if(!!(value & KeyUsageExt::nonRepudiation)) {
            keyUsageString += "nonRepudiation,";
        }
        if(!!(value & KeyUsageExt::keyEncipherment)) {
            keyUsageString += "keyEncipherment,";
        }
        if(!!(value & KeyUsageExt::dataEncipherment)) {
            keyUsageString += "dataEncipherment,";
        }
        if(!!(value & KeyUsageExt::keyAgreement)) {
            keyUsageString += "keyAgreement,";
        }
        if(!!(value & KeyUsageExt::keyCertSign)) {
            keyUsageString += "keyCertSign,";
        }
        if(!!(value & KeyUsageExt::cRLSign)) {
            keyUsageString += "cRLSign,";
        }
        if(!!(value & KeyUsageExt::encipherOnly)) {
            keyUsageString += "encipherOnly,";
        }
        if(!!(value & KeyUsageExt::decipherOnly)) {
            keyUsageString += "decipherOnly,";
        }
        
        ca.getConfig()->setValue(type2Section(type, true), "keyUsage", 
                                 keyUsageString.erase(keyUsageString.length()-1));
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "keyUsage");
    }
}

bool
KeyUsageExt::valid() const
{
    if(!isPresent()) return true;

    if(!validKeyUsage(value)) return false;
    
    return true;
}

blocxx::StringArray
KeyUsageExt::verify() const
{
    blocxx::StringArray result;

    if(!isPresent()) return result;

    if(!validKeyUsage(value)) {
        result.append(Format("invalid value '%1' for keyUsage", value).toString());
    }

    LOGIT_DEBUG_STRINGARRAY("KeyUsageExt::verify()", result);
    return result;
}

blocxx::StringArray
KeyUsageExt::dump() const
{
    StringArray result;
    result.append("KeyUsageExt::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    String ku;
    ku.format("%04x", value);
    result.append("KeyUsage = 0x" + ku);

    return result;
}


bool
KeyUsageExt::validKeyUsage(blocxx::UInt32 keyUsage) const
{
    UInt32 mask = 0x80FF;
    if( (keyUsage&mask) != keyUsage || keyUsage == 0) {
        return false;
    }
    return true;
}


// ###################################################################

        
NsCertTypeExt::NsCertTypeExt()
    : BitExtension()
{}

NsCertTypeExt::NsCertTypeExt(CAConfig* caConfig, Type type)
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

NsCertTypeExt::NsCertTypeExt(blocxx::UInt32 nsCertTypes)
    : BitExtension(nsCertTypes)
{
    if(value > 0xFF || value == 0) {
        BLOCXX_THROW(limal::ValueException, "invalid value for NsCertTypeExt");
    }
    setPresent(true);
}

NsCertTypeExt::NsCertTypeExt(const NsCertTypeExt& extension)
    : BitExtension(extension)
{}

NsCertTypeExt::~NsCertTypeExt()
{}


NsCertTypeExt&
NsCertTypeExt::operator=(const NsCertTypeExt& extension)
{
    if(this == &extension) return *this;

    BitExtension::operator=(extension);

    return *this;
}

void
NsCertTypeExt::setNsCertType(blocxx::UInt32 nsCertTypes)
{
    if(nsCertTypes > 0xFF || nsCertTypes == 0) {
        BLOCXX_THROW(limal::ValueException, 
                     Format("invalid value for NsCertTypeExt: %1", nsCertTypes).c_str());
    }
    setValue(nsCertTypes);
    setPresent(true);
}

blocxx::UInt32
NsCertTypeExt::getNsCertType() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "NsCertTypeExt is not present");
    }
    return value;
}

bool
NsCertTypeExt::isEnabledFor(NsCertType nsCertType) const
{
    // if ! isPresent() ... throw exceptions?
    if(!isPresent()) return false;

    return !!(value & nsCertType);
}

void
NsCertTypeExt::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid NsCertTypeExt object");
        BLOCXX_THROW(limal::ValueException, "invalid NsCertTypeExt object");
    }

    // This extension is not supported by type CRL
    if(type == E_CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent()) {
        String nsCertTypeString;

        if(isCritical()) nsCertTypeString += "critical,";

        if(!!(value & NsCertTypeExt::client)) {
            nsCertTypeString += "client,";
        }
        if(!!(value & NsCertTypeExt::server)) {
            nsCertTypeString += "server,";
        }
        if(!!(value & NsCertTypeExt::email)) {
            nsCertTypeString += "email,";
        }
        if(!!(value & NsCertTypeExt::objsign)) {
            nsCertTypeString += "objsign,";
        }
        if(!!(value & NsCertTypeExt::reserved)) {
            nsCertTypeString += "reserved,";
        }
        if(!!(value & NsCertTypeExt::sslCA)) {
            nsCertTypeString += "sslCA,";
        }
        if(!!(value & NsCertTypeExt::emailCA)) {
            nsCertTypeString += "emailCA,";
        }
        if(!!(value & NsCertTypeExt::objCA)) {
            nsCertTypeString += "objCA,";
        }
        
        ca.getConfig()->setValue(type2Section(type, true), "nsCertType", 
                                 nsCertTypeString.erase(nsCertTypeString.length()-1));
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "nsCertType");
    }
}

bool
NsCertTypeExt::valid() const
{
    if(!isPresent()) return true;

    if(value > 0xFF || value == 0) return false;
    
    return true;
}

blocxx::StringArray
NsCertTypeExt::verify() const
{
    blocxx::StringArray result;

    if(!isPresent()) return result;

    if(value > 0xFF || value == 0) {
        result.append(Format("invalid value '%1' for nsCertType", value).toString());
    }
    LOGIT_DEBUG_STRINGARRAY("NsCertTypeExt::verify()", result);
    return result;
}

blocxx::StringArray
NsCertTypeExt::dump() const
{
    StringArray result;
    result.append("NsCertTypeExt::dump()");

    result.appendArray(ExtensionBase::dump());
    if(!isPresent()) return result;

    String nsct;
    nsct.format("%02x", value);
    result.append("NsCertType = 0x" + nsct);

    return result;
}

}
}

