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

using namespace limal;
using namespace limal::ca_mgm;
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

KeyUsageExtension::KeyUsageExtension(CA& ca, Type type)
    : BitExtension()
{
    // These types are not supported by this object
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = ca.getConfig()->exists(type2Section(type, true), "keyUsage");
    if(p) {
        blocxx::UInt32 keyUsage = 0;
        
        String ku = ca.getConfig()->getValue(type2Section(type, true), "keyUsage");
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
        }
        setKeyUsage(keyUsage);
    }
    setPresent(p);
}

KeyUsageExtension::KeyUsageExtension(blocxx::UInt32 keyUsage)
    : BitExtension(keyUsage)
{
    if(!validKeyUsage(getValue())) {
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

    ExtensionBase::operator=(extension);

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
    return getValue();
}

bool
KeyUsageExtension::isEnabledFor(KeyUsage ku) const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "KeyUsageExtension is not present");
    }
    
    return !!(getValue() & ku);
}

void
KeyUsageExtension::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid KeyUsageExtension object");
        BLOCXX_THROW(limal::ValueException, "invalid KeyUsageExtension object");
    }

    // This extension is not supported by type CRL
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent()) {
        String keyUsageString;

        if(isCritical()) keyUsageString += "critical,";

        if(!!(getValue() & KeyUsageExtension::digitalSignature)) {
            keyUsageString += "digitalSignature,";
        }
        if(!!(getValue() & KeyUsageExtension::nonRepudiation)) {
            keyUsageString += "nonRepudiation,";
        }
        if(!!(getValue() & KeyUsageExtension::keyEncipherment)) {
            keyUsageString += "keyEncipherment,";
        }
        if(!!(getValue() & KeyUsageExtension::dataEncipherment)) {
            keyUsageString += "dataEncipherment,";
        }
        if(!!(getValue() & KeyUsageExtension::keyAgreement)) {
            keyUsageString += "keyAgreement,";
        }
        if(!!(getValue() & KeyUsageExtension::keyCertSign)) {
            keyUsageString += "keyCertSign,";
        }
        if(!!(getValue() & KeyUsageExtension::cRLSign)) {
            keyUsageString += "cRLSign,";
        }
        if(!!(getValue() & KeyUsageExtension::encipherOnly)) {
            keyUsageString += "encipherOnly,";
        }
        if(!!(getValue() & KeyUsageExtension::decipherOnly)) {
            keyUsageString += "decipherOnly,";
        }
        
        ca.getConfig()->setValue(type2Section(type, true), "keyUsage", 
                                 keyUsageString.erase(keyUsageString.length()-2));
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "keyUsage");
    }
}

bool
KeyUsageExtension::valid() const
{
    if(!isPresent()) return true;

    if(!validKeyUsage(getValue())) return false;
    
    return true;
}

blocxx::StringArray
KeyUsageExtension::verify() const
{
    blocxx::StringArray result;

    if(!isPresent()) return result;

    if(!validKeyUsage(getValue())) {
        result.append(Format("invalid value '%1' for keyUsage", getValue()).toString());
    }
    return result;
}

bool
KeyUsageExtension::validKeyUsage(blocxx::UInt32 keyUsage) const
{
    if(keyUsage > 0x1FF || keyUsage == 0) {
        return false;
    }
    return true;
}


// ###################################################################

        
NsCertTypeExtension::NsCertTypeExtension()
    : BitExtension()
{}

NsCertTypeExtension::NsCertTypeExtension(CA& ca, Type type)
    : BitExtension()
{
    // These types are not supported by this object
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = ca.getConfig()->exists(type2Section(type, true), "nsCertType");
    if(p) {
        blocxx::UInt32 bits = 0;
        
        String ct = ca.getConfig()->getValue(type2Section(type, true), "nsCertType");
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
        }
        setNsCertType(bits);
    }
    setPresent(p);
}

NsCertTypeExtension::NsCertTypeExtension(blocxx::UInt32 nsCertTypes)
    : BitExtension(nsCertTypes)
{
    if(getValue() > 0xFF || getValue() == 0) {
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

    ExtensionBase::operator=(extension);

    return *this;
}

void
NsCertTypeExtension::setNsCertType(blocxx::UInt32 nsCertTypes)
{
    if(nsCertTypes > 0xFF || getValue() == 0) {
        BLOCXX_THROW(limal::ValueException, "invalid value for NsCertTypeExtension");
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
    return getValue();
}

bool
NsCertTypeExtension::isEnabledFor(NsCertType nsCertType) const
{
    // if ! isPresent() ... throw exceptions?
    if(!isPresent()) return false;

    return !!(getValue() & nsCertType);
}

void
NsCertTypeExtension::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid NsCertTypeExtension object");
        BLOCXX_THROW(limal::ValueException, "invalid NsCertTypeExtension object");
    }

    // This extension is not supported by type CRL
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent()) {
        String nsCertTypeString;

        if(isCritical()) nsCertTypeString += "critical,";

        if(!!(getValue() & NsCertTypeExtension::client)) {
            nsCertTypeString += "client,";
        }
        if(!!(getValue() & NsCertTypeExtension::server)) {
            nsCertTypeString += "server,";
        }
        if(!!(getValue() & NsCertTypeExtension::email)) {
            nsCertTypeString += "email,";
        }
        if(!!(getValue() & NsCertTypeExtension::objsign)) {
            nsCertTypeString += "objsign,";
        }
        if(!!(getValue() & NsCertTypeExtension::reserved)) {
            nsCertTypeString += "reserved,";
        }
        if(!!(getValue() & NsCertTypeExtension::sslCA)) {
            nsCertTypeString += "sslCA,";
        }
        if(!!(getValue() & NsCertTypeExtension::emailCA)) {
            nsCertTypeString += "emailCA,";
        }
        if(!!(getValue() & NsCertTypeExtension::objCA)) {
            nsCertTypeString += "objCA,";
        }
        
        ca.getConfig()->setValue(type2Section(type, true), "nsCertType", 
                                 nsCertTypeString.erase(nsCertTypeString.length()-2));
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "nsCertType");
    }
}

bool
NsCertTypeExtension::valid() const
{
    if(!isPresent()) return true;

    if(getValue() > 0xFF || getValue() == 0) return false;
    
    return true;
}

blocxx::StringArray
NsCertTypeExtension::verify() const
{
    blocxx::StringArray result;

    if(!isPresent()) return result;

    if(getValue() > 0xFF || getValue() == 0) {
        result.append(Format("invalid value '%1' for nsCertType", getValue()).toString());
    }
    return result;
}

// ###################################################################

ExtendedKeyUsageExtension::ExtendedKeyUsageExtension()
    : BitExtension(), oids(StringList())
{}

ExtendedKeyUsageExtension::ExtendedKeyUsageExtension(CA& ca, Type type)
    : BitExtension()
{
    // These types are not supported by this object
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    bool p = ca.getConfig()->exists(type2Section(type, true), "extendedKeyUsage");
    if(p) {
        blocxx::UInt32 bits = 0;
        ValueCheck check = initOIDCheck();

        String ct = ca.getConfig()->getValue(type2Section(type, true), "extendedKeyUsage");
        StringArray sp = PerlRegEx("\\s*,\\s*").split(ct);

        if(sp[0].equalsIgnoreCase("critical")) setCritical(true);

        StringArray::const_iterator it = sp.begin();
        for(; it != sp.end(); ++it) {
            if((*it).equalsIgnoreCase("serverAuth"))            bits |= serverAuth; 
            else if((*it).equalsIgnoreCase("clientAuth"))       bits |= clientAuth; 
            else if((*it).equalsIgnoreCase("codeSigning"))      bits |= codeSigning; 
            else if((*it).equalsIgnoreCase("emailProtection"))  bits |= emailProtection; 
            else if((*it).equalsIgnoreCase("timeStamping"))     bits |= timeStamping; 
            else if((*it).equalsIgnoreCase("msCodeInd"))        bits |= msCodeInd; 
            else if((*it).equalsIgnoreCase("msCodeCom"))        bits |= msCodeCom; 
            else if((*it).equalsIgnoreCase("msCTLSign"))        bits |= msCTLSign; 
            else if((*it).equalsIgnoreCase("msSGC"))            bits |= msSGC; 
            else if((*it).equalsIgnoreCase("msEFS"))            bits |= msEFS; 
            else if((*it).equalsIgnoreCase("nsSGC"))            bits |= nsSGC; 
            else if(check.isValid(*it)) {
                oids.push_back(*it);
            }
        }
        setExtendedKeyUsage(bits);
    }
    setPresent(p);
}

ExtendedKeyUsageExtension::ExtendedKeyUsageExtension(blocxx::UInt32 extKeyUsages, 
                                                     const StringList& additionalOIDs)
    : BitExtension(extKeyUsages), oids(additionalOIDs)
{
    if(getValue() == 0 && oids.empty()) {
        BLOCXX_THROW(limal::ValueException, "invalid ExtendedKeyUsageExtension.");
    }

    if(getValue() > 0x7FF) {
        BLOCXX_THROW(limal::ValueException, "invalid extKeyUsages value");
    }
    
    ValueCheck oidCheck = initOIDCheck();

    StringList::const_iterator it = oids.begin();
    for(;it != oids.end(); it++) {
        if(!oidCheck.isValid(*it)) {
            BLOCXX_THROW(limal::ValueException, Format("invalid additionalOID(%1)", *it).c_str());
        }
    }
    setPresent(true);
}

ExtendedKeyUsageExtension::ExtendedKeyUsageExtension(const ExtendedKeyUsageExtension& extension)
    : BitExtension(extension), oids(extension.oids)
{}

ExtendedKeyUsageExtension::~ExtendedKeyUsageExtension()
{}


ExtendedKeyUsageExtension&
ExtendedKeyUsageExtension::operator=(const ExtendedKeyUsageExtension& extension)
{
    if(this == &extension) return *this;

    ExtensionBase::operator=(extension);
    oids = extension.oids;

    return *this;
}

void
ExtendedKeyUsageExtension::setExtendedKeyUsage(blocxx::UInt32 extKeyUsages)
{
    if(extKeyUsages > 0x7FF) {
        BLOCXX_THROW(limal::ValueException, "invalid extKeyUsages value");
    }

    setValue(extKeyUsages);
    setPresent(true);
}

blocxx::UInt32
ExtendedKeyUsageExtension::getExtendedKeyUsage() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "ExtendedKeyUsageExtension is not present");
    }
    return getValue();
}
        
bool
ExtendedKeyUsageExtension::isEnabledFor(ExtendedKeyUsage extKeyUsage) const
{
    // if ! isPresent() ... throw exceptions?
    if(!isPresent()) return false;

    return !!(getValue() & extKeyUsage);
}

void
ExtendedKeyUsageExtension::setAdditionalOIDs(const StringList& additionalOIDs)
{
    ValueCheck oidCheck = initOIDCheck();
    
    StringList::const_iterator it = oids.begin();
    for(;it != oids.end(); it++) {
        if(!oidCheck.isValid(*it)) {
            BLOCXX_THROW(limal::ValueException, Format("invalid additionalOID(%1)", *it).c_str());
        }
    }
    
    oids = additionalOIDs;
    setPresent(true);
}

StringList
ExtendedKeyUsageExtension::getAdditionalOIDs() const
{
    if(!isPresent()) {
        BLOCXX_THROW(limal::RuntimeException, "ExtendedKeyUsageExtension is not present");
    }
    return oids;
}

void
ExtendedKeyUsageExtension::addAdditionalOID(String oid)
{
    ValueCheck oidCheck = initOIDCheck();
    if(!oidCheck.isValid(oid)) {
        BLOCXX_THROW(limal::ValueException, Format("invalid OID(%1)", oid).c_str());
    }
    oids.push_back(oid);
    setPresent(true);    
}

/*
  bool
  ExtendedKeyUsageExtension::deleteAdditionalOID(String oid)
  {
  return false;
  }
*/
  
void
ExtendedKeyUsageExtension::commit2Config(CA& ca, Type type) const
{
    if(!valid()) {
        LOGIT_ERROR("invalid ExtendedKeyUsageExtension object");
        BLOCXX_THROW(limal::ValueException, "invalid ExtendedKeyUsageExtension object");
    }

    // This extension is not supported by type CRL
    if(type == CRL) {
        LOGIT_ERROR("wrong type" << type);
        BLOCXX_THROW(limal::ValueException, Format("wrong type: %1", type).c_str());
    }

    if(isPresent()) {
        String extendedKeyUsageString;

        if(isCritical()) extendedKeyUsageString += "critical,";

        if(!!(getValue() & ExtendedKeyUsageExtension::serverAuth)) {
            extendedKeyUsageString += "serverAuth,";
        }
        if(!!(getValue() & ExtendedKeyUsageExtension::clientAuth)) {
            extendedKeyUsageString += "clientAuth,";
        }
        if(!!(getValue() & ExtendedKeyUsageExtension::codeSigning)) {
            extendedKeyUsageString += "codeSigning,";
        }
        if(!!(getValue() & ExtendedKeyUsageExtension::emailProtection)) {
            extendedKeyUsageString += "emailProtection,";
        }
        if(!!(getValue() & ExtendedKeyUsageExtension::timeStamping)) {
            extendedKeyUsageString += "timeStamping,";
        }
        if(!!(getValue() & ExtendedKeyUsageExtension::msCodeInd)) {
            extendedKeyUsageString += "msCodeInd,";
        }
        if(!!(getValue() & ExtendedKeyUsageExtension::msCodeCom)) {
            extendedKeyUsageString += "msCodeCom,";
        }
        if(!!(getValue() & ExtendedKeyUsageExtension::msCTLSign)) {
            extendedKeyUsageString += "msCTLSign,";
        }
        if(!!(getValue() & ExtendedKeyUsageExtension::msSGC)) {
            extendedKeyUsageString += "msSGC,";
        }
        if(!!(getValue() & ExtendedKeyUsageExtension::msEFS)) {
            extendedKeyUsageString += "msEFS,";
        }
        if(!!(getValue() & ExtendedKeyUsageExtension::nsSGC)) {
            extendedKeyUsageString += "nsSGC,";
        }
        StringList::const_iterator it = oids.begin();
        for(; it != oids.end(); ++it) {
            extendedKeyUsageString += (*it)+",";
        }

        ca.getConfig()->setValue(type2Section(type, true), "extendedKeyUsage", 
                                 extendedKeyUsageString.erase(extendedKeyUsageString.length()-2));
    } else {
        ca.getConfig()->deleteValue(type2Section(type, true), "extendedKeyUsage");
    }
}

bool
ExtendedKeyUsageExtension::valid() const
{
    if(!isPresent()) return true;

    if(getValue() == 0 && oids.empty()) {
        return false;
    }

    if(getValue() > 0x7FF) {
        return false;
    }
    
    ValueCheck oidCheck = initOIDCheck();

    StringList::const_iterator it = oids.begin();
    for(;it != oids.end(); it++) {
        if(!oidCheck.isValid(*it)) {
            return false;
        }
    }
    return true;
}

blocxx::StringArray
ExtendedKeyUsageExtension::verify() const
{
    blocxx::StringArray result;

    if(!isPresent()) return result;

    if(getValue() == 0 && oids.empty()) {
        result.append(String("invalid ExtendedKeyUsageExtension."));
    }

    if(getValue() > 0x7FF) {
        result.append(Format("invalid extKeyUsages value(%1)", getValue()).toString());
    }
    
    ValueCheck oidCheck = initOIDCheck();

    StringList::const_iterator it = oids.begin();
    for(;it != oids.end(); it++) {
        if(!oidCheck.isValid(*it)) {
            result.append(Format("invalid additionalOID(%1)", *it).toString());
        }
    }
    return result;
}
