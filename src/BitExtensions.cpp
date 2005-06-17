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
#include  <limal/ValueRegExCheck.hpp>
#include  <limal/Exception.hpp>
#include  <blocxx/Format.hpp>

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
}

KeyUsageExtension::KeyUsageExtension(blocxx::UInt32 keyUsage)
    : BitExtension(keyUsage)
{
    if(getValue() > 0x1FF || getValue() == 0) {
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
    if(keyUsage > 0x1FF || getValue() == 0) {
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
    // if ! isPresent() ... throw exceptions?
    if(!isPresent()) return false;

    return !!(getValue() & ku);
}

void
KeyUsageExtension::commit2Config(CA& ca, Type type)
{
}

bool
KeyUsageExtension::valid() const
{
    if(!isPresent()) return true;

    if(getValue() > 0x1FF || getValue() == 0) return false;
    
    return true;
}

blocxx::StringArray
KeyUsageExtension::verify() const
{
    blocxx::StringArray result;

    if(!isPresent()) return result;

    if(getValue() > 0x1FF || getValue() == 0) {
        result.append(Format("invalid value '%1' for keyUsage", getValue()).toString());
    }
    return result;
}

// ###################################################################

        
NsCertTypeExtension::NsCertTypeExtension()
    : BitExtension()
{}

NsCertTypeExtension::NsCertTypeExtension(CA& ca, Type type)
    : BitExtension()
{}

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
NsCertTypeExtension::commit2Config(CA& ca, Type type)
{
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

inline static ValueCheck initExtendedKeyUsageOIDCheck() {
    ValueCheck checkOID =
        ValueCheck(new ValueRegExCheck("^([0-9]+\\.)+[0-9]+$"));
    
    return checkOID;
}

ExtendedKeyUsageExtension::ExtendedKeyUsageExtension()
    : BitExtension(), oids(StringList())
{}

ExtendedKeyUsageExtension::ExtendedKeyUsageExtension(CA& ca, Type type)
    : BitExtension()
{
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
    
    ValueCheck oidCheck = initExtendedKeyUsageOIDCheck();

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
    if(extKeyUsages == 0 && oids.empty()) {
        BLOCXX_THROW(limal::ValueException, "invalid value for extKeyUsages.");
    }

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
    if(getValue() == 0 && additionalOIDs.empty()) {
        BLOCXX_THROW(limal::ValueException, "invalid value for additionalOIDs.");
    }

    ValueCheck oidCheck = initExtendedKeyUsageOIDCheck();
    
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
    ValueCheck oidCheck = initExtendedKeyUsageOIDCheck();
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
ExtendedKeyUsageExtension::commit2Config(CA& ca, Type type)
{
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
    
    ValueCheck oidCheck = initExtendedKeyUsageOIDCheck();

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
    
    ValueCheck oidCheck = initExtendedKeyUsageOIDCheck();

    StringList::const_iterator it = oids.begin();
    for(;it != oids.end(); it++) {
        if(!oidCheck.isValid(*it)) {
            result.append(Format("invalid additionalOID(%1)", *it).toString());
        }
    }
    return result;
}
